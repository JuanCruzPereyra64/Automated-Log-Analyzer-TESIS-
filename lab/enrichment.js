// lab/enrichment.js
// Etapa de enriquecimiento con Threat Intelligence (AbuseIPDB) para el pipeline
// SIEM/SOAR del laboratorio. Implementa los requisitos de diseño:
//   R7 · Tratar el agotamiento de cuota de AbuseIPDB: caché de resultados,
//        lectura de Retry-After ante HTTP 429 y campo de estado del enriquecimiento.
//   R9 · Usar el puntaje de AbuseIPDB como condición de respuesta:
//        >= 75 bloqueo automático; 50-74 revisión humana; < 50 sin bloqueo automático.
//
// El módulo es agnóstico del transporte (recibe una función `httpGet`) para
// poder verificarse con respuestas simuladas sin depender de la red ni de una
// clave de API.

const CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutos

class Enricher {
  constructor({ httpGet, apiKey = null, cache = new Map(), now = Date.now } = {}) {
    if (typeof httpGet !== 'function') throw new Error('httpGet requerido');
    this.httpGet = httpGet;         // async (ip) -> { status, headers, body }
    this.apiKey = apiKey;
    this.cache = cache;             // Map<ip, { data, expires }>
    this.now = now;                 // inyectable para pruebas
    this.quotaBlockedUntil = 0;     // ts hasta el que no se consulta (tras 429)
    this.stats = { calls: 0, cache_hits: 0, quota_429: 0, errors: 0 };
  }

  // R7: enriquecer una IP tratando el agotamiento de cuota de forma explícita.
  async enrich(ip) {
    // (1) caché de resultados
    const hit = this.cache.get(ip);
    if (hit && hit.expires > this.now()) {
      this.stats.cache_hits += 1;
      return { ...hit.data, enrichment_status: 'cached' };
    }
    // (2) cuota agotada: no se reintenta hasta que expire Retry-After
    if (this.now() < this.quotaBlockedUntil) {
      return {
        ip, threat_score: null, is_known_threat: false, country: null,
        enrichment_status: 'degraded_quota',
        retry_after_s: Math.ceil((this.quotaBlockedUntil - this.now()) / 1000),
      };
    }
    // (3) consulta
    this.stats.calls += 1;
    let resp;
    try {
      resp = await this.httpGet(ip, this.apiKey);
    } catch (err) {
      this.stats.errors += 1;
      return {
        ip, threat_score: 0, is_known_threat: false, country: null,
        enrichment_status: 'error', error: String(err && err.message || err),
      };
    }
    if (resp.status === 429) {
      // R7: leer Retry-After y registrar el estado; el flujo continúa.
      this.stats.quota_429 += 1;
      const ra = parseInt(resp.headers && resp.headers['retry-after'], 10) || 0;
      this.quotaBlockedUntil = this.now() + ra * 1000;
      return {
        ip, threat_score: null, is_known_threat: false, country: null,
        enrichment_status: 'degraded_quota', retry_after_s: ra,
      };
    }
    if (resp.status !== 200) {
      this.stats.errors += 1;
      return {
        ip, threat_score: 0, is_known_threat: false, country: null,
        enrichment_status: `error_${resp.status}`,
      };
    }
    const d = (resp.body && resp.body.data) || {};
    const score = Number(d.abuseConfidenceScore);
    const data = {
      ip,
      threat_score: Number.isFinite(score) ? score : null,
      is_known_threat: Number.isFinite(score) && score >= 75,
      country: d.countryCode || null,
      enrichment_status: 'ok',
    };
    this.cache.set(ip, { data, expires: this.now() + CACHE_TTL_MS });
    return data;
  }
}

// R9: bifurcación de la respuesta a partir del puntaje de AbuseIPDB.
function decideResponse(enriched) {
  const s = enriched && enriched.threat_score;
  if (s === null || s === undefined) {
    return {
      decision: 'no_auto_block',
      reason: 'enriquecimiento no disponible (sin puntaje) → sin bloqueo automático',
    };
  }
  if (s >= 75) {
    return { decision: 'auto_block', reason: `abuseConfidenceScore ${s} >= 75` };
  }
  if (s >= 50) {
    return { decision: 'human_review', reason: `abuseConfidenceScore ${s} en el rango 50-74` };
  }
  return { decision: 'no_auto_block', reason: `abuseConfidenceScore ${s} < 50` };
}

module.exports = { Enricher, decideResponse, CACHE_TTL_MS };
