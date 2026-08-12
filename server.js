'use strict';

/**
 * rca-alert-fraud-detection-service
 *
 * Fraud detection and alerting service. Scores payment transactions in real time
 * against a configurable rule engine, raises fraud alerts with severity
 * classification, and routes them to downstream AIOps incident channels.
 *
 * AIOps RCA demo service — in-memory storage only, no external dependencies.
 */

const express = require('express');
const { randomUUID } = require('crypto');

const app = express();

const PORT = parseInt(process.env.PORT || '3000', 10);
const SERVICE_NAME = process.env.SERVICE_NAME || 'rca-alert-fraud-detection-service';
const SERVICE_VERSION = process.env.SERVICE_VERSION || '1.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const API_KEY = process.env.API_KEY || '';
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '100', 10);
const FAILURE_RATE = parseFloat(process.env.FAILURE_RATE || '0.05');

const STARTED_AT = Date.now();

// ---------------------------------------------------------------------------
// Structured logging
// ---------------------------------------------------------------------------

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };

function log(level, message, meta = {}) {
  if (LEVELS[level] > (LEVELS[LOG_LEVEL] ?? 2)) return;
  process.stdout.write(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      level,
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      message,
      ...meta,
    }) + '\n'
  );
}

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

/** @type {Map<string, object>} alertId -> alert */
const alerts = new Map();
/** @type {Map<string, object>} transactionId -> scored transaction */
const transactions = new Map();
/** @type {Map<string, {count: number, resetAt: number}>} */
const rateBuckets = new Map();

const metrics = {
  requests_total: 0,
  requests_failed_total: 0,
  transactions_scored_total: 0,
  alerts_raised_total: 0,
  alerts_escalated_total: 0,
  alerts_resolved_total: 0,
  simulated_failures_total: 0,
};

// ---------------------------------------------------------------------------
// Fraud rule engine
// ---------------------------------------------------------------------------

/**
 * Each rule inspects a transaction and returns a risk contribution (0-100)
 * plus a human-readable reason when it fires.
 */
const RULES = [
  {
    id: 'HIGH_AMOUNT',
    description: 'Transaction amount exceeds the high-value threshold',
    weight: 35,
    evaluate: (tx) => (tx.amount > 5000 ? 'amount above 5000' : null),
  },
  {
    id: 'VELOCITY',
    description: 'Too many transactions from the same account in a short window',
    weight: 25,
    evaluate: (tx) => {
      const windowStart = Date.now() - 60_000;
      const recent = [...transactions.values()].filter(
        (t) => t.accountId === tx.accountId && Date.parse(t.scoredAt) >= windowStart
      );
      return recent.length >= 3 ? `${recent.length} transactions in last 60s` : null;
    },
  },
  {
    id: 'GEO_MISMATCH',
    description: 'Billing country differs from the transaction origin country',
    weight: 20,
    evaluate: (tx) =>
      tx.billingCountry && tx.originCountry && tx.billingCountry !== tx.originCountry
        ? `billing ${tx.billingCountry} != origin ${tx.originCountry}`
        : null,
  },
  {
    id: 'HIGH_RISK_COUNTRY',
    description: 'Origin country is on the elevated-risk list',
    weight: 15,
    evaluate: (tx) =>
      HIGH_RISK_COUNTRIES.has((tx.originCountry || '').toUpperCase())
        ? `origin ${tx.originCountry} is high risk`
        : null,
  },
  {
    id: 'NEW_DEVICE',
    description: 'Transaction originates from a previously unseen device',
    weight: 10,
    evaluate: (tx) => {
      if (!tx.deviceId) return null;
      const seen = [...transactions.values()].some(
        (t) => t.accountId === tx.accountId && t.deviceId === tx.deviceId
      );
      return seen ? null : `unseen device ${tx.deviceId}`;
    },
  },
  {
    id: 'ODD_HOUR',
    description: 'Transaction occurs during low-activity overnight hours',
    weight: 5,
    evaluate: (tx) => {
      const hour = new Date(tx.occurredAt || Date.now()).getUTCHours();
      return hour >= 1 && hour <= 5 ? `occurred at ${hour}:00 UTC` : null;
    },
  },
];

const HIGH_RISK_COUNTRIES = new Set(['NG', 'RU', 'KP', 'IR', 'VE']);

/** Maps a 0-100 risk score onto an alert severity band. */
function classifySeverity(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  return 'low';
}

/** Runs every rule against a transaction and returns the aggregate assessment. */
function scoreTransaction(tx) {
  const triggered = [];
  let score = 0;

  for (const rule of RULES) {
    const reason = rule.evaluate(tx);
    if (reason) {
      score += rule.weight;
      triggered.push({ ruleId: rule.id, weight: rule.weight, reason });
    }
  }

  score = Math.min(100, score);
  return { score, severity: classifySeverity(score), triggeredRules: triggered };
}

// ---------------------------------------------------------------------------
// Demo failure injection — gives the AIOps RCA demo realistic error signal
// ---------------------------------------------------------------------------

function simulateFailure(rate = FAILURE_RATE) {
  if (Math.random() < rate) {
    metrics.simulated_failures_total += 1;
    const err = new Error('Downstream fraud-scoring engine timed out');
    err.status = 503;
    err.code = 'SCORING_ENGINE_TIMEOUT';
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || randomUUID();
  req.startTime = Date.now();
  res.setHeader('X-Request-Id', req.id);
  metrics.requests_total += 1;

  res.on('finish', () => {
    if (res.statusCode >= 500) metrics.requests_failed_total += 1;
    log('info', 'request completed', {
      requestId: req.id,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - req.startTime,
    });
  });

  next();
});

// In-memory fixed-window rate limiter, keyed by client IP.
app.use((req, res, next) => {
  if (req.path === '/health' || req.path === '/ready' || req.path === '/metrics') return next();

  const key = req.ip || 'unknown';
  const now = Date.now();
  let bucket = rateBuckets.get(key);

  if (!bucket || now >= bucket.resetAt) {
    bucket = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
    rateBuckets.set(key, bucket);
  }

  bucket.count += 1;
  res.setHeader('X-RateLimit-Limit', RATE_LIMIT_MAX);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, RATE_LIMIT_MAX - bucket.count));

  if (bucket.count > RATE_LIMIT_MAX) {
    log('warn', 'rate limit exceeded', { requestId: req.id, client: key });
    return res.status(429).json({ error: 'RATE_LIMIT_EXCEEDED', requestId: req.id });
  }

  next();
});

// Optional API key auth — enabled only when API_KEY is configured.
app.use((req, res, next) => {
  if (!API_KEY) return next();
  if (req.path === '/health' || req.path === '/ready') return next();

  if (req.headers['x-api-key'] !== API_KEY) {
    return res.status(401).json({ error: 'UNAUTHORIZED', requestId: req.id });
  }

  next();
});

// ---------------------------------------------------------------------------
// Observability endpoints
// ---------------------------------------------------------------------------

app.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    env: NODE_ENV,
    uptimeSeconds: Math.floor((Date.now() - STARTED_AT) / 1000),
  });
});

app.get('/ready', (req, res) => {
  res.json({
    status: 'READY',
    service: SERVICE_NAME,
    rulesLoaded: RULES.length,
    openAlerts: [...alerts.values()].filter((a) => a.status === 'open').length,
  });
});

app.get('/metrics', (req, res) => {
  const bySeverity = { low: 0, medium: 0, high: 0, critical: 0 };
  for (const alert of alerts.values()) bySeverity[alert.severity] += 1;

  res.json({
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    uptimeSeconds: Math.floor((Date.now() - STARTED_AT) / 1000),
    counters: metrics,
    gauges: {
      alerts_total: alerts.size,
      transactions_total: transactions.size,
      alerts_by_severity: bySeverity,
    },
  });
});

// ---------------------------------------------------------------------------
// Fraud scoring endpoints
// ---------------------------------------------------------------------------

app.get('/rules', (req, res) => {
  res.json({
    count: RULES.length,
    rules: RULES.map((r) => ({ id: r.id, description: r.description, weight: r.weight })),
  });
});

app.post('/transactions/score', (req, res, next) => {
  try {
    simulateFailure();

    const { accountId, amount, currency, originCountry, billingCountry, deviceId, occurredAt } =
      req.body || {};

    if (!accountId || typeof accountId !== 'string') {
      return res.status(400).json({ error: 'accountId is required', requestId: req.id });
    }
    if (typeof amount !== 'number' || Number.isNaN(amount) || amount <= 0) {
      return res.status(400).json({ error: 'amount must be a positive number', requestId: req.id });
    }

    const tx = {
      id: randomUUID(),
      accountId,
      amount,
      currency: currency || 'USD',
      originCountry: originCountry || null,
      billingCountry: billingCountry || null,
      deviceId: deviceId || null,
      occurredAt: occurredAt || new Date().toISOString(),
      scoredAt: new Date().toISOString(),
    };

    const assessment = scoreTransaction(tx);
    tx.riskScore = assessment.score;
    tx.severity = assessment.severity;
    transactions.set(tx.id, tx);
    metrics.transactions_scored_total += 1;

    // Anything at medium or above becomes an actionable fraud alert.
    let alert = null;
    if (assessment.severity !== 'low') {
      alert = {
        id: randomUUID(),
        transactionId: tx.id,
        accountId: tx.accountId,
        amount: tx.amount,
        currency: tx.currency,
        riskScore: assessment.score,
        severity: assessment.severity,
        status: 'open',
        triggeredRules: assessment.triggeredRules,
        escalated: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      alerts.set(alert.id, alert);
      metrics.alerts_raised_total += 1;
      log('warn', 'fraud alert raised', {
        requestId: req.id,
        alertId: alert.id,
        severity: alert.severity,
        riskScore: alert.riskScore,
      });
    }

    res.status(201).json({
      transactionId: tx.id,
      riskScore: assessment.score,
      severity: assessment.severity,
      triggeredRules: assessment.triggeredRules,
      alertId: alert ? alert.id : null,
      requestId: req.id,
    });
  } catch (err) {
    next(err);
  }
});

app.get('/transactions/:id', (req, res) => {
  const tx = transactions.get(req.params.id);
  if (!tx) return res.status(404).json({ error: 'TRANSACTION_NOT_FOUND', requestId: req.id });
  res.json(tx);
});

// ---------------------------------------------------------------------------
// Alert lifecycle endpoints
// ---------------------------------------------------------------------------

app.get('/alerts', (req, res) => {
  const { severity, status, accountId } = req.query;
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);

  let results = [...alerts.values()];
  if (severity) results = results.filter((a) => a.severity === severity);
  if (status) results = results.filter((a) => a.status === status);
  if (accountId) results = results.filter((a) => a.accountId === accountId);

  results.sort((a, b) => b.riskScore - a.riskScore);

  res.json({ count: results.length, alerts: results.slice(0, limit), requestId: req.id });
});

app.get('/alerts/:id', (req, res) => {
  const alert = alerts.get(req.params.id);
  if (!alert) return res.status(404).json({ error: 'ALERT_NOT_FOUND', requestId: req.id });
  res.json(alert);
});

app.post('/alerts/:id/escalate', (req, res, next) => {
  try {
    simulateFailure();

    const alert = alerts.get(req.params.id);
    if (!alert) return res.status(404).json({ error: 'ALERT_NOT_FOUND', requestId: req.id });
    if (alert.status === 'resolved') {
      return res.status(409).json({ error: 'ALERT_ALREADY_RESOLVED', requestId: req.id });
    }

    const channel = (req.body && req.body.channel) || 'aiops-incidents';
    alert.escalated = true;
    alert.status = 'escalated';
    alert.escalatedTo = channel;
    alert.escalatedAt = new Date().toISOString();
    alert.updatedAt = alert.escalatedAt;
    metrics.alerts_escalated_total += 1;

    log('warn', 'alert escalated', {
      requestId: req.id,
      alertId: alert.id,
      channel,
      severity: alert.severity,
    });

    res.json({ escalated: true, alert, requestId: req.id });
  } catch (err) {
    next(err);
  }
});

app.post('/alerts/:id/resolve', (req, res) => {
  const alert = alerts.get(req.params.id);
  if (!alert) return res.status(404).json({ error: 'ALERT_NOT_FOUND', requestId: req.id });

  alert.status = 'resolved';
  alert.resolution = (req.body && req.body.resolution) || 'confirmed_legitimate';
  alert.resolvedAt = new Date().toISOString();
  alert.updatedAt = alert.resolvedAt;
  metrics.alerts_resolved_total += 1;

  log('info', 'alert resolved', {
    requestId: req.id,
    alertId: alert.id,
    resolution: alert.resolution,
  });

  res.json({ resolved: true, alert, requestId: req.id });
});

// ---------------------------------------------------------------------------
// Chargeback intake — links issuer chargebacks back to the originating alert
// ---------------------------------------------------------------------------

/** @type {Map<string, object>} chargebackId -> chargeback */
const chargebacks = new Map();

metrics.chargebacks_received_total = 0;
metrics.chargebacks_matched_total = 0;

const CHARGEBACK_REASONS = new Set([
  'fraudulent',
  'product_not_received',
  'duplicate',
  'subscription_canceled',
  'unrecognized',
]);

app.post('/chargebacks', (req, res, next) => {
  try {
    simulateFailure();

    const { transactionId, reason, amount, issuerRef } = req.body || {};

    if (!transactionId) {
      return res.status(400).json({ error: 'transactionId is required', requestId: req.id });
    }
    if (!CHARGEBACK_REASONS.has(reason)) {
      return res.status(400).json({
        error: 'INVALID_REASON',
        allowed: [...CHARGEBACK_REASONS],
        requestId: req.id,
      });
    }

    const tx = transactions.get(transactionId);
    const linkedAlert = tx
      ? [...alerts.values()].find((a) => a.transactionId === transactionId)
      : null;

    const chargeback = {
      id: randomUUID(),
      transactionId,
      reason,
      amount: typeof amount === 'number' ? amount : tx ? tx.amount : null,
      issuerRef: issuerRef || null,
      matchedTransaction: Boolean(tx),
      alertId: linkedAlert ? linkedAlert.id : null,
      receivedAt: new Date().toISOString(),
    };

    chargebacks.set(chargeback.id, chargeback);
    metrics.chargebacks_received_total += 1;
    if (tx) metrics.chargebacks_matched_total += 1;

    // A fraudulent chargeback on an alert we already raised confirms the alert
    // was a true positive; one with no alert is a miss worth flagging loudly.
    if (reason === 'fraudulent') {
      if (linkedAlert) {
        linkedAlert.chargebackId = chargeback.id;
        linkedAlert.outcome = 'true_positive';
        linkedAlert.updatedAt = new Date().toISOString();
      } else if (tx) {
        log('error', 'fraudulent chargeback with no prior alert', {
          requestId: req.id,
          transactionId,
          riskScore: tx.riskScore,
        });
      }
    }

    res.status(201).json({ chargeback, requestId: req.id });
  } catch (err) {
    next(err);
  }
});

app.get('/chargebacks', (req, res) => {
  const { reason, transactionId } = req.query;
  let results = [...chargebacks.values()];
  if (reason) results = results.filter((c) => c.reason === reason);
  if (transactionId) results = results.filter((c) => c.transactionId === transactionId);
  results.sort((a, b) => Date.parse(b.receivedAt) - Date.parse(a.receivedAt));
  res.json({ count: results.length, chargebacks: results, requestId: req.id });
});

app.get('/chargebacks/:id', (req, res) => {
  const chargeback = chargebacks.get(req.params.id);
  if (!chargeback) {
    return res.status(404).json({ error: 'CHARGEBACK_NOT_FOUND', requestId: req.id });
  }
  res.json(chargeback);
});

// ---------------------------------------------------------------------------
// Account risk profiles — rolls transaction and alert history into one view
// ---------------------------------------------------------------------------

const RISK_BANDS = [
  { max: 24, band: 'trusted' },
  { max: 49, band: 'standard' },
  { max: 74, band: 'elevated' },
  { max: 100, band: 'restricted' },
];

function bandFor(score) {
  return (RISK_BANDS.find((b) => score <= b.max) || RISK_BANDS[RISK_BANDS.length - 1]).band;
}

/**
 * Builds a rolling risk profile for an account. The profile score blends the
 * account's mean transaction risk with penalties for confirmed-fraud outcomes
 * and escalations, so repeat offenders drift upward over time.
 */
function buildAccountProfile(accountId) {
  const accountTxs = [...transactions.values()].filter((t) => t.accountId === accountId);
  const accountAlerts = [...alerts.values()].filter((a) => a.accountId === accountId);

  if (accountTxs.length === 0) return null;

  const meanRisk =
    accountTxs.reduce((sum, t) => sum + (t.riskScore || 0), 0) / accountTxs.length;
  const totalValue = accountTxs.reduce((sum, t) => sum + t.amount, 0);
  const escalated = accountAlerts.filter((a) => a.escalated).length;
  const confirmedFraud = accountAlerts.filter(
    (a) => a.resolution === 'confirmed_fraud' || a.outcome === 'true_positive'
  ).length;

  const penalty = Math.min(40, escalated * 5 + confirmedFraud * 15);
  const profileScore = Math.min(100, Math.round(meanRisk + penalty));

  return {
    accountId,
    profileScore,
    riskBand: bandFor(profileScore),
    transactionCount: accountTxs.length,
    alertCount: accountAlerts.length,
    escalatedAlerts: escalated,
    confirmedFraudAlerts: confirmedFraud,
    meanRiskScore: Math.round(meanRisk * 10) / 10,
    totalTransactedValue: Math.round(totalValue * 100) / 100,
    firstSeen: accountTxs.reduce((a, t) => (t.scoredAt < a ? t.scoredAt : a), accountTxs[0].scoredAt),
    lastSeen: accountTxs.reduce((a, t) => (t.scoredAt > a ? t.scoredAt : a), accountTxs[0].scoredAt),
    generatedAt: new Date().toISOString(),
  };
}

app.get('/accounts/:accountId/risk', (req, res) => {
  const profile = buildAccountProfile(req.params.accountId);
  if (!profile) {
    return res.status(404).json({ error: 'ACCOUNT_NOT_FOUND', requestId: req.id });
  }
  res.json({ ...profile, requestId: req.id });
});

app.get('/accounts/:accountId/transactions', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
  const results = [...transactions.values()]
    .filter((t) => t.accountId === req.params.accountId)
    .sort((a, b) => Date.parse(b.scoredAt) - Date.parse(a.scoredAt))
    .slice(0, limit);
  res.json({ count: results.length, transactions: results, requestId: req.id });
});

app.get('/accounts/high-risk', (req, res) => {
  const threshold = parseInt(req.query.threshold || '60', 10);
  const accountIds = [...new Set([...transactions.values()].map((t) => t.accountId))];
  const profiles = accountIds
    .map(buildAccountProfile)
    .filter((p) => p && p.profileScore >= threshold)
    .sort((a, b) => b.profileScore - a.profileScore);
  res.json({ threshold, count: profiles.length, accounts: profiles, requestId: req.id });
});

// ---------------------------------------------------------------------------
// Trusted-party allowlist — suppress alerts for verified accounts and devices
// ---------------------------------------------------------------------------

/** @type {Map<string, object>} "account:<id>" | "device:<id>" -> entry */
const allowlist = new Map();

metrics.allowlist_suppressions_total = 0;

const ALLOWLIST_TYPES = new Set(['account', 'device']);

function allowlistKey(type, value) {
  return `${type}:${value}`;
}

/** Returns the matching allowlist entry for a transaction, or null. */
function findAllowlistMatch(tx) {
  const candidates = [
    allowlistKey('account', tx.accountId),
    tx.deviceId ? allowlistKey('device', tx.deviceId) : null,
  ].filter(Boolean);

  for (const key of candidates) {
    const entry = allowlist.get(key);
    if (!entry) continue;
    if (entry.expiresAt && Date.parse(entry.expiresAt) < Date.now()) {
      allowlist.delete(key);
      continue;
    }
    return entry;
  }
  return null;
}

app.post('/allowlist', (req, res) => {
  const { type, value, reason, expiresAt } = req.body || {};

  if (!ALLOWLIST_TYPES.has(type)) {
    return res
      .status(400)
      .json({ error: 'INVALID_TYPE', allowed: [...ALLOWLIST_TYPES], requestId: req.id });
  }
  if (!value || typeof value !== 'string') {
    return res.status(400).json({ error: 'value is required', requestId: req.id });
  }

  const entry = {
    key: allowlistKey(type, value),
    type,
    value,
    reason: reason || 'manually_verified',
    expiresAt: expiresAt || null,
    addedAt: new Date().toISOString(),
  };

  allowlist.set(entry.key, entry);
  log('info', 'allowlist entry added', { requestId: req.id, key: entry.key, reason: entry.reason });

  res.status(201).json({ entry, requestId: req.id });
});

app.get('/allowlist', (req, res) => {
  const now = Date.now();
  const entries = [...allowlist.values()].filter(
    (e) => !e.expiresAt || Date.parse(e.expiresAt) >= now
  );
  res.json({ count: entries.length, entries, requestId: req.id });
});

app.delete('/allowlist/:type/:value', (req, res) => {
  const key = allowlistKey(req.params.type, req.params.value);
  if (!allowlist.delete(key)) {
    return res.status(404).json({ error: 'ALLOWLIST_ENTRY_NOT_FOUND', requestId: req.id });
  }
  log('info', 'allowlist entry removed', { requestId: req.id, key });
  res.json({ removed: true, key, requestId: req.id });
});

/**
 * Allowlist-aware scoring. Still computes and stores the full risk assessment
 * so analytics stay intact, but suppresses alert creation for trusted parties.
 */
app.post('/transactions/screen', (req, res, next) => {
  try {
    simulateFailure();

    const { accountId, amount } = req.body || {};
    if (!accountId || typeof amount !== 'number' || amount <= 0) {
      return res
        .status(400)
        .json({ error: 'accountId and a positive amount are required', requestId: req.id });
    }

    const tx = {
      id: randomUUID(),
      accountId,
      amount,
      currency: req.body.currency || 'USD',
      originCountry: req.body.originCountry || null,
      billingCountry: req.body.billingCountry || null,
      deviceId: req.body.deviceId || null,
      occurredAt: req.body.occurredAt || new Date().toISOString(),
      scoredAt: new Date().toISOString(),
    };

    const assessment = scoreTransaction(tx);
    tx.riskScore = assessment.score;
    tx.severity = assessment.severity;
    transactions.set(tx.id, tx);
    metrics.transactions_scored_total += 1;

    const match = findAllowlistMatch(tx);
    if (match) {
      metrics.allowlist_suppressions_total += 1;
      tx.suppressedBy = match.key;
      log('info', 'alert suppressed by allowlist', {
        requestId: req.id,
        transactionId: tx.id,
        key: match.key,
        riskScore: assessment.score,
      });
      return res.status(201).json({
        transactionId: tx.id,
        riskScore: assessment.score,
        severity: assessment.severity,
        suppressed: true,
        suppressedBy: match,
        alertId: null,
        requestId: req.id,
      });
    }

    let alertId = null;
    if (assessment.severity !== 'low') {
      const alert = {
        id: randomUUID(),
        transactionId: tx.id,
        accountId: tx.accountId,
        amount: tx.amount,
        currency: tx.currency,
        riskScore: assessment.score,
        severity: assessment.severity,
        status: 'open',
        triggeredRules: assessment.triggeredRules,
        escalated: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      alerts.set(alert.id, alert);
      metrics.alerts_raised_total += 1;
      alertId = alert.id;
    }

    res.status(201).json({
      transactionId: tx.id,
      riskScore: assessment.score,
      severity: assessment.severity,
      suppressed: false,
      alertId,
      requestId: req.id,
    });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

app.use((req, res) => {
  res.status(404).json({ error: 'NOT_FOUND', path: req.originalUrl, requestId: req.id });
});

app.use((err, req, res, next) => {
  const status = err.status || 500;
  log('error', 'request failed', {
    requestId: req.id,
    code: err.code || 'INTERNAL_ERROR',
    error: err.message,
    status,
  });
  res.status(status).json({
    error: err.code || 'INTERNAL_ERROR',
    message: err.message,
    requestId: req.id,
  });
});

// ---------------------------------------------------------------------------
// Bootstrap + graceful shutdown
// ---------------------------------------------------------------------------

let server;

if (require.main === module) {
  server = app.listen(PORT, () => {
    log('info', 'service started', { port: PORT, env: NODE_ENV, rules: RULES.length });
  });

  const shutdown = (signal) => {
    log('info', 'shutdown signal received', { signal });
    if (!server) process.exit(0);
    server.close(() => {
      log('info', 'server closed cleanly');
      process.exit(0);
    });
    setTimeout(() => {
      log('error', 'forced shutdown after timeout');
      process.exit(1);
    }, 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

module.exports = app;
