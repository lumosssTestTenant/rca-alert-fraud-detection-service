'use strict';

// Deterministic tests: disable injected demo failures and auth before loading the app.
process.env.FAILURE_RATE = '0';
process.env.LOG_LEVEL = 'error';
process.env.RATE_LIMIT_MAX = '10000';
delete process.env.API_KEY;

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const app = require('../server');

let server;
let baseUrl;

test.before(async () => {
  await new Promise((resolve) => {
    server = http.createServer(app).listen(0, () => {
      baseUrl = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

async function call(method, path, body) {
  const res = await fetch(baseUrl + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : null };
}

/** A transaction that trips HIGH_AMOUNT + GEO_MISMATCH + HIGH_RISK_COUNTRY + NEW_DEVICE. */
function highRiskTx(overrides = {}) {
  return {
    accountId: `acct-${Math.random().toString(36).slice(2, 10)}`,
    amount: 9500,
    currency: 'USD',
    originCountry: 'NG',
    billingCountry: 'US',
    deviceId: `dev-${Math.random().toString(36).slice(2, 10)}`,
    occurredAt: '2026-08-12T12:00:00Z',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

test('GET /health returns UP with service metadata', async () => {
  const res = await call('GET', '/health');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.status, 'UP');
  assert.strictEqual(res.body.service, 'rca-alert-fraud-detection-service');
  assert.ok(typeof res.body.uptimeSeconds === 'number');
});

test('GET /ready reports the loaded rule set', async () => {
  const res = await call('GET', '/ready');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.status, 'READY');
  assert.strictEqual(res.body.rulesLoaded, 6);
});

test('GET /metrics exposes counters and gauges', async () => {
  const res = await call('GET', '/metrics');
  assert.strictEqual(res.status, 200);
  assert.ok(res.body.counters);
  assert.ok(res.body.gauges);
  assert.ok(typeof res.body.counters.requests_total === 'number');
  assert.ok(res.body.gauges.alerts_by_severity);
});

test('every response carries an X-Request-Id header', async () => {
  const res = await call('GET', '/health');
  assert.ok(res.headers.get('x-request-id'));
});

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

test('GET /rules lists all six weighted rules', async () => {
  const res = await call('GET', '/rules');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.count, 6);
  const ids = res.body.rules.map((r) => r.id);
  assert.deepStrictEqual(ids.sort(), [
    'GEO_MISMATCH',
    'HIGH_AMOUNT',
    'HIGH_RISK_COUNTRY',
    'NEW_DEVICE',
    'ODD_HOUR',
    'VELOCITY',
  ]);
});

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

test('POST /transactions/score rejects a missing accountId', async () => {
  const res = await call('POST', '/transactions/score', { amount: 100 });
  assert.strictEqual(res.status, 400);
  assert.match(res.body.error, /accountId/);
});

test('POST /transactions/score rejects a non-positive amount', async () => {
  const res = await call('POST', '/transactions/score', { accountId: 'acct-x', amount: -5 });
  assert.strictEqual(res.status, 400);
  assert.match(res.body.error, /amount/);
});

test('POST /transactions/score raises a critical alert for a high-risk transaction', async () => {
  const res = await call('POST', '/transactions/score', highRiskTx());
  assert.strictEqual(res.status, 201);
  assert.strictEqual(res.body.severity, 'critical');
  assert.strictEqual(res.body.riskScore, 80);
  assert.ok(res.body.alertId);

  const ids = res.body.triggeredRules.map((r) => r.ruleId);
  assert.ok(ids.includes('HIGH_AMOUNT'));
  assert.ok(ids.includes('GEO_MISMATCH'));
  assert.ok(ids.includes('HIGH_RISK_COUNTRY'));
});

test('POST /transactions/score does not alert on a low-risk transaction', async () => {
  const accountId = `acct-lowrisk-${Date.now()}`;
  // Seed the device so NEW_DEVICE cannot fire on the assertion request.
  const deviceId = 'dev-known';
  await call('POST', '/transactions/score', {
    accountId,
    amount: 10,
    originCountry: 'US',
    billingCountry: 'US',
    deviceId,
    occurredAt: '2026-08-12T12:00:00Z',
  });

  const res = await call('POST', '/transactions/score', {
    accountId,
    amount: 25,
    originCountry: 'US',
    billingCountry: 'US',
    deviceId,
    occurredAt: '2026-08-12T12:00:00Z',
  });

  assert.strictEqual(res.status, 201);
  assert.strictEqual(res.body.severity, 'low');
  assert.strictEqual(res.body.riskScore, 0);
  assert.strictEqual(res.body.alertId, null);
});

test('GET /transactions/:id returns a scored transaction, 404 otherwise', async () => {
  const scored = await call('POST', '/transactions/score', highRiskTx());
  const found = await call('GET', `/transactions/${scored.body.transactionId}`);
  assert.strictEqual(found.status, 200);
  assert.strictEqual(found.body.id, scored.body.transactionId);

  const missing = await call('GET', '/transactions/does-not-exist');
  assert.strictEqual(missing.status, 404);
  assert.strictEqual(missing.body.error, 'TRANSACTION_NOT_FOUND');
});

// ---------------------------------------------------------------------------
// Alert lifecycle
// ---------------------------------------------------------------------------

test('GET /alerts filters by severity and accountId', async () => {
  const tx = highRiskTx();
  await call('POST', '/transactions/score', tx);

  const res = await call('GET', `/alerts?severity=critical&accountId=${tx.accountId}`);
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.count, 1);
  assert.strictEqual(res.body.alerts[0].accountId, tx.accountId);
  assert.strictEqual(res.body.alerts[0].severity, 'critical');
});

test('GET /alerts/:id returns 404 for an unknown alert', async () => {
  const res = await call('GET', '/alerts/nope');
  assert.strictEqual(res.status, 404);
  assert.strictEqual(res.body.error, 'ALERT_NOT_FOUND');
});

test('POST /alerts/:id/escalate routes the alert to an incident channel', async () => {
  const scored = await call('POST', '/transactions/score', highRiskTx());
  const res = await call('POST', `/alerts/${scored.body.alertId}/escalate`, {
    channel: 'aiops-incidents',
  });

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.escalated, true);
  assert.strictEqual(res.body.alert.status, 'escalated');
  assert.strictEqual(res.body.alert.escalatedTo, 'aiops-incidents');
});

test('POST /alerts/:id/resolve closes the alert with a resolution', async () => {
  const scored = await call('POST', '/transactions/score', highRiskTx());
  const res = await call('POST', `/alerts/${scored.body.alertId}/resolve`, {
    resolution: 'confirmed_fraud',
  });

  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.resolved, true);
  assert.strictEqual(res.body.alert.status, 'resolved');
  assert.strictEqual(res.body.alert.resolution, 'confirmed_fraud');
});

test('escalating a resolved alert returns 409', async () => {
  const scored = await call('POST', '/transactions/score', highRiskTx());
  await call('POST', `/alerts/${scored.body.alertId}/resolve`, {});

  const res = await call('POST', `/alerts/${scored.body.alertId}/escalate`, {});
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.body.error, 'ALERT_ALREADY_RESOLVED');
});

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

test('unknown routes return a 404 envelope', async () => {
  const res = await call('GET', '/no/such/route');
  assert.strictEqual(res.status, 404);
  assert.strictEqual(res.body.error, 'NOT_FOUND');
  assert.strictEqual(res.body.path, '/no/such/route');
});
