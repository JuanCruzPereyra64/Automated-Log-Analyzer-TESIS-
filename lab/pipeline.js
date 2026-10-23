// Pipeline SIEM-SOAR (nodo Code, ejecucion serializada por Cron cada T segundos)
// Implementa: R1 (ventana deslizante en BD), R2 (offset por archivo/inodo),
// R4 (validacion de IP), R5 (lista de exclusion), R6 (TTL), R8 (bitacora de corrida).
// Multi-fuente: auth.log (SSH), security/alerts.log (iptables DROP / port scan),
// apache_access/all.log (SQLi). Correlacion generalizada a TODAS las reglas activas.
const fs = require('fs');
const pg = require('pg');
const http = require('http');

const AUTH_LOG = '/home/node/.n8n-files/auth.log';
const SEC_LOG = '/home/node/.n8n-files/security/alerts.log';
const APACHE_LOG = '/home/node/.n8n-files/apache_access/all.log';
const BLOCK_AGENT = 'http://lab-victim:9000';
const PG = { host: 'lab-postgres', port: 5432, user: 'admin', password: 'admin', database: 'security_monitoring' };

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const EXCLUDE = new Set(['10.50.0.1', '127.0.0.1']); // R5: gateway/admin
const GRACE = 180; // s: horizonte de ingesta que tolera el sondeo por lotes (evita re-alertar)

const pool = new pg.Pool(PG);
const out = {};

function ensureSchema() {
  return pool.query(`
    CREATE TABLE IF NOT EXISTS parsed_events (
      id BIGSERIAL PRIMARY KEY,
      event_ts TIMESTAMPTZ NOT NULL,
      rule_id INTEGER,
      rule_name TEXT,
      src_ip INET,
      raw_log TEXT,
      ingest_ts TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS file_offsets (
      path TEXT PRIMARY KEY,
      inode TEXT,
      read_offset BIGINT,
      updated_at TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS lab_config (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE IF NOT EXISTS pipeline_runs (
      id BIGSERIAL PRIMARY KEY,
      run_ts TIMESTAMPTZ DEFAULT now(),
      arm TEXT,
      lines_read INTEGER,
      events_parsed INTEGER,
      alerts_created INTEGER
    );
    INSERT INTO lab_config(key,value) VALUES ('arm','n8n') ON CONFLICT (key) DO NOTHING;
  `);
}

function stampFor(year, monName, day, hh, mm, ss) {
  const months = { Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11 };
  const m = months[monName];
  if (m === undefined) return null;
  return new Date(Date.UTC(year, m, Number(day), Number(hh), Number(mm), Number(ss)));
}

// --- R2: lectura incremental con offset por archivo+inodo ---
async function readNew(path) {
  let st;
  try { st = fs.statSync(path); } catch (e) { return { lines: [], inode: null, newOffset: 0, exists: false }; }
  const inode = String(st.ino);
  const prev = (await pool.query(`SELECT inode, read_offset FROM file_offsets WHERE path=$1`, [path])).rows[0];
  let start = (prev && prev.inode === inode) ? Number(prev.read_offset) : 0;
  const size = st.size;
  if (size < start) start = 0;
  let text = '';
  const len = size - start;
  if (len > 0) {
    const fd = fs.openSync(path, 'r');
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, start);
    fs.closeSync(fd);
    text = buf.toString('utf8');
  }
  let newOffset = size;
  let lines = text.split('\n');
  if (text.length > 0 && !text.endsWith('\n')) {
    const last = lines.pop();
    newOffset = size - Buffer.byteLength(last, 'utf8');
  }
  await pool.query(`INSERT INTO file_offsets(path,inode,read_offset,updated_at) VALUES($1,$2,$3,now())
    ON CONFLICT (path) DO UPDATE SET inode=EXCLUDED.inode, read_offset=EXCLUDED.read_offset, updated_at=now()`,
    [path, inode, newOffset]);
  return { lines, inode, newOffset, exists: true };
}

// --- Parsers por fuente ---
const RE_AUTH = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+\S+\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?\S+ from ((?:\d{1,3}\.){3}\d{1,3}) port/;
function parseAuth(line, year) {
  const m = line.match(RE_AUTH);
  if (!m) return null;
  return { src: m[6], ts: stampFor(year, m[1], m[2], m[3], m[4], m[5]) };
}

const RE_SEC = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+\S+\s+kernel:\s+iptables DROP:.*SRC=((?:\d{1,3}\.){3}\d{1,3})/;
function parseSec(line, year) {
  const m = line.match(RE_SEC);
  if (!m) return null;
  return { src: m[6], ts: stampFor(year, m[1], m[2], m[3], m[4], m[5]) };
}

const RE_APACHE = /^((?:\d{1,3}\.){3}\d{1,3})\s+\S+\s+\S+\s+\[(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+[^\]]*\]\s+"([A-Z]+)\s+(\S+)\s+HTTP\/[\d.]+"/;
function parseApache(line) {
  const m = line.match(RE_APACHE);
  if (!m) return null;
  const ts = stampFor(Number(m[4]), m[3], m[2], m[5], m[6], m[7]);
  return { src: m[1], ts, method: m[8], path: m[9] };
}

// Fuente -> parser estructural (extrae src/ts). El patron de CADA regla
// habilitada se evalua sobre la linea cruda, de modo que una linea puede
// disparar varias reglas y una linea benigna no genera ningun evento.
const SOURCES = [
  { path: AUTH_LOG, parser: (l, y) => parseAuth(l, y) },
  { path: SEC_LOG, parser: (l, y) => parseSec(l, y) },
  { path: APACHE_LOG, parser: (l) => parseApache(l) },
];

async function main() {
  await ensureSchema();
  const armRow = (await pool.query(`SELECT value FROM lab_config WHERE key='arm'`)).rows[0];
  const arm = armRow ? armRow.value : 'n8n';
  out.arm = arm;

  const rules = (await pool.query(`SELECT id,name,pattern,severity,threshold,time_window FROM detection_rules WHERE enabled=true`)).rows;
  const year = new Date().getUTCFullYear();
  const ruleRes = rules
    .map((r) => { try { return { rule: r, re: new RegExp(r.pattern, 'i') }; } catch (e) { return null; } })
    .filter(Boolean);

  let linesRead = 0, eventsParsed = 0;
  for (const src of SOURCES) {
    const { lines } = await readNew(src.path);
    for (const line of lines) {
      if (!line.trim()) continue;
      linesRead++;
      const p = src.parser(line, year);
      if (!p || !p.src || !p.ts) continue;
      if (!IPV4.test(p.src)) continue;             // R4: validacion estricta IPv4
      for (const { rule, re } of ruleRes) {        // una linea puede disparar varias reglas
        if (!re.test(line)) continue;
        await pool.query(
          `INSERT INTO parsed_events(event_ts, rule_id, rule_name, src_ip, raw_log) VALUES($1,$2,$3,$4,$5)`,
          [p.ts.toISOString(), rule.id, rule.name, p.src, line]);
        eventsParsed++;
      }
    }
  }

  // --- Correlacion sobre ventana deslizante (R1), para TODAS las reglas activas ---
  let alertsCreated = 0;
  for (const rule of rules) {
    const win = Number(rule.time_window) || 300;
    const thr = Number(rule.threshold) || 5;
    // R1 ventana deslizante anclada al evento mas reciente de cada (regla, IP):
    // asi una rafaga procesada en lote (sondeo periodico) no se descarta por
    // llegar "vieja" cuando time_window es corta (p.ej. SQLi = 1s). El horizonte
    // de ingesta GRACE hace que el evento expire y no re-alerte indefinidamente.
    const hits = (await pool.query(
      `WITH recent AS (
         SELECT src_ip, event_ts FROM parsed_events
         WHERE rule_id=$1 AND ingest_ts > now() - ($4 || ' seconds')::interval
       ),
       anch AS (SELECT src_ip, max(event_ts) AS m FROM recent GROUP BY src_ip)
       SELECT r.src_ip::text AS ip, count(*)::int AS c, min(r.event_ts) AS first_ts, max(r.event_ts) AS last_ts
       FROM recent r JOIN anch a USING (src_ip)
       WHERE r.event_ts > a.m - ($2 || ' seconds')::interval
       GROUP BY r.src_ip HAVING count(*) >= $3`, [rule.id, win, thr, GRACE])).rows;

    for (const h of hits) {
      const ip = h.ip;
      if (EXCLUDE.has(ip)) continue; // R5
      // dedup: no re-alertar la misma IP dentro de la ventana+horizonte
      const dup = (await pool.query(
        `SELECT 1 FROM alerts WHERE source_ip=$1 AND category=$2 AND timestamp > now() - ($3 || ' seconds')::interval LIMIT 1`,
        [ip, rule.name, win + GRACE + 60])).rows.length > 0;
      if (dup) continue;

      const desc = `${rule.name}: ${h.c} eventos en ${win}s desde ${ip}`;
      const a = await pool.query(
        `INSERT INTO alerts(timestamp, severity, category, source_host, source_ip, target_host, event_count, description, raw_log, status)
         VALUES (now(), $1, $2, 'lab-victim', $3, 'lab-victim', $4, $5, $6, 'new') RETURNING id, timestamp`,
        [rule.severity, rule.name, ip, h.c, desc, `matched ${rule.name} from ${ip}`]);
      alertsCreated++;
      out.last_alert_id = a.rows[0].id;

      // attack_patterns
      await pool.query(
        `INSERT INTO attack_patterns(pattern_type, source_ip, target_host, occurrence_count, is_blocked)
         VALUES ($1,$2,'lab-victim',$3,false)
         ON CONFLICT (source_ip, pattern_type) DO UPDATE SET last_seen=now(), occurrence_count=attack_patterns.occurrence_count+$3`,
        [rule.name, ip, h.c]);

      // --- Respuesta activa (brazo n8n), para todas las reglas ---
      if (arm === 'n8n') {
        try {
          await new Promise((res) => {
            const req = http.get(`${BLOCK_AGENT}/block?ip=${ip}&ttl=600`, (r) => { r.resume(); r.on('end', res); });
            req.on('error', res); req.setTimeout(5000, () => { req.destroy(); res(); });
          });
          await pool.query(`UPDATE attack_patterns SET is_blocked=true WHERE source_ip=$1 AND pattern_type=$2`, [ip, rule.name]);
          out.blocked = (out.blocked || 0) + 1;
        } catch (e) { out.block_error = String(e); }
      }
    }
  }

  // --- R8: bitacora de corrida ---
  await pool.query(`INSERT INTO pipeline_runs(arm,lines_read,events_parsed,alerts_created) VALUES($1,$2,$3,$4)`,
    [arm, linesRead, eventsParsed, alertsCreated]);

  out.lines_read = linesRead;
  out.events_parsed = eventsParsed;
  out.alerts_created = alertsCreated;
  return finish(linesRead, eventsParsed, alertsCreated, arm);
}

function finish(linesRead, eventsParsed, alertsCreated, arm) {
  out.lines_read = linesRead; out.events_parsed = eventsParsed; out.alerts_created = alertsCreated;
  return [{ json: out }];
}

try {
  return await main();
} finally {
  await pool.end();
}
