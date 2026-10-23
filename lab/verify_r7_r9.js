// lab/verify_r7_r9.js
// Verificación de los requisitos R7 (agotamiento de cuota de AbuseIPDB) y R9
// (puntaje como condición de respuesta) mediante respuestas simuladas.
//
// Criterios de la Tabla 8 del informe:
//   R7 · "Simular una respuesta 429; el flujo debe continuar y registrar el estado."
//   R9 · "Casos con puntaje alto y bajo; comprobar la bifurcación."
//
// Además se incluye una comprobación de red en vivo contra api.abuseipdb.com
// (sin clave) para evidenciar que la salida a internet está habilitada y que
// el flujo degrada de forma controlada (HTTP 401) sin interrumpirse.

const http = require('http');
const fs = require('fs');
const path = require('path');
const { Enricher, decideResponse } = require('./enrichment');

const results = [];
function check(id, desc, cond, detail) {
  results.push({ id, desc, pass: !!cond, detail });
  console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${id} — ${desc}${detail ? '  :: ' + detail : ''}`);
}

// --- servidor simulado de AbuseIPDB ---
function startMock(responder) {
  return new Promise((resolve) => {
    const srv = http.createServer(responder);
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port }));
  });
}

// cliente HTTP real (usa la pila de red de Node) contra el servidor simulado
function makeHttpGet(port) {
  return (ip) => new Promise((resolve, reject) => {
    const req = http.get(
      { host: '127.0.0.1', port, path: `/api/v2/check?ipAddress=${ip}` },
      (res) => {
        let b = '';
        res.on('data', (c) => { b += c; });
        res.on('end', () => {
          let body = {};
          try { body = JSON.parse(b); } catch (e) { /* noop */ }
          resolve({ status: res.statusCode, headers: res.headers, body });
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(5000, () => { req.destroy(new Error('timeout')); });
  });
}

async function main() {
  console.log('== Verificación R7 (cuota / HTTP 429 / caché / estado) ==');
  // El mock devuelve 429 con Retry-After: 60 para toda consulta
  const { srv: srv429, port: port429 } = await startMock((req, res) => {
    res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
    res.end(JSON.stringify({ errors: [{ detail: 'Rate limit exceeded' }] }));
  });

  const enr429 = new Enricher({ httpGet: makeHttpGet(port429) });
  let r = await enr429.enrich('10.50.0.200');
  check('R7.1', 'HTTP 429 → el flujo continúa y registra estado degraded_quota',
    r.enrichment_status === 'degraded_quota', `status=${r.enrichment_status}`);
  check('R7.2', 'Retry-After se lee y registra (60 s)',
    r.retry_after_s === 60, `retry_after_s=${r.retry_after_s}`);
  // segunda consulta: debe servirse del cortocircuito de cuota, sin re-llamar
  r = await enr429.enrich('10.50.0.201');
  check('R7.3', 'Cuota agotada → no reintenta dentro de Retry-After (sin nueva llamada)',
    r.enrichment_status === 'degraded_quota' && enr429.stats.calls === 1,
    `calls=${enr429.stats.calls}`);
  srv429.close();

  // Mock 200 con puntaje alto
  const { srv: srv200, port: port200 } = await startMock((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ data: { abuseConfidenceScore: 92, countryCode: 'RU' } }));
  });
  const enr200 = new Enricher({ httpGet: makeHttpGet(port200), apiKey: 'test' });
  r = await enr200.enrich('10.50.0.202');
  check('R7.4', 'HTTP 200 → puntaje y país registrados', r.enrichment_status === 'ok' && r.threat_score === 92 && r.country === 'RU',
    `status=${r.enrichment_status} score=${r.threat_score} country=${r.country}`);
  const r2 = await enr200.enrich('10.50.0.202');
  check('R7.5', 'Segunda consulta de la misma IP → servida desde caché',
    r2.enrichment_status === 'cached' && enr200.stats.cache_hits === 1,
    `status=${r2.enrichment_status} hits=${enr200.stats.cache_hits}`);
  srv200.close();

  console.log('\n== Verificación R9 (bifurcación por puntaje) ==');
  const hi = decideResponse({ threat_score: 92 });
  check('R9.1', 'Puntaje 92 (>=75) → bloqueo automático', hi.decision === 'auto_block', hi.reason);
  const mid = decideResponse({ threat_score: 60 });
  check('R9.2', 'Puntaje 60 (50-74) → revisión humana', mid.decision === 'human_review', mid.reason);
  const lo = decideResponse({ threat_score: 20 });
  check('R9.3', 'Puntaje 20 (<50) → sin bloqueo automático', lo.decision === 'no_auto_block', lo.reason);
  const na = decideResponse({ threat_score: null });
  check('R9.4', 'Sin puntaje (cuota agotada) → sin bloqueo automático', na.decision === 'no_auto_block', na.reason);
  const edge = decideResponse({ threat_score: 75 });
  check('R9.5', 'Borde: puntaje 75 → bloqueo automático', edge.decision === 'auto_block', edge.reason);

  console.log('\n== Comprobación de red en vivo (salida a internet) ==');
  const live = new Enricher({
    httpGet: (ip) => new Promise((resolve, reject) => {
      const req = http.get(
        { host: 'api.abuseipdb.com', path: `/api/v2/check?ipAddress=${ip}`, headers: { Accept: 'application/json' } },
        (res) => { let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: {} })); }
      );
      req.on('error', reject);
      req.setTimeout(8000, () => { req.destroy(new Error('timeout')); });
    }),
  });
  try {
    const lr = await live.enrich('118.25.6.39');
    // Sin clave la API responde 401; lo relevante es que la red es alcanzable y
    // el flujo degrada de forma controlada.
    check('NET.1', 'api.abuseipdb.com alcanzable; degradación controlada sin clave',
      lr.enrichment_status === 'error_401', `status=${lr.enrichment_status}`);
  } catch (e) {
    check('NET.1', 'api.abuseipdb.com alcanzable', false, String(e.message));
  }

  const passed = results.filter((r) => r.pass).length;
  console.log(`\nRESUMEN: ${passed}/${results.length} comprobaciones aprobadas`);

  const out = {
    generated_at: new Date().toISOString(),
    criteria: { R7: 'Simular 429: el flujo continúa y registra el estado',
                R9: 'Puntaje alto/bajo: comprobar la bifurcación' },
    total: results.length, passed,
    results,
  };
  const outPath = path.join(__dirname, 'results', 'r7_r9_verification.json');
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2), 'utf-8');
  console.log(`Escrito: ${outPath}`);
  process.exit(passed === results.length ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(2); });
