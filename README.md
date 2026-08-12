# rca-alert-fraud-detection-service

Fraud detection and alerting service that scores payment transactions in real time, raises fraud alerts with severity classification, and routes them to downstream AIOps incident channels.

> **AIOps RCA demo service.** Storage is in-memory only — there is no database. The service deliberately injects a small rate of downstream failures so that incident/RCA tooling has realistic error signal to work with.

---

## Quick Start

```bash
# Local (Node 18+)
npm install
cp .env.example .env
npm start
# → http://localhost:3000

# Docker
docker compose up --build

# Docker + nginx reverse proxy
docker compose --profile proxy up --build
# → http://localhost:8080
```

Smoke test:

```bash
curl -s localhost:3000/health | jq

curl -s -X POST localhost:3000/transactions/score \
  -H 'Content-Type: application/json' \
  -d '{"accountId":"acct-1001","amount":9500,"currency":"USD","originCountry":"NG","billingCountry":"US","deviceId":"dev-xyz"}' | jq
```

---

## Architecture

```
        ┌────────────┐
client ─▶│   nginx    │ :80  (optional, `proxy` profile)
        └─────┬──────┘
              │ proxy_pass
        ┌─────▼───────────────────────────────────┐
        │  Express app (:3000)                    │
        │  ┌───────────────────────────────────┐  │
        │  │ requestId → logger → rate limiter │  │
        │  │ → optional API key auth           │  │
        │  └────────────────┬──────────────────┘  │
        │                   ▼                     │
        │      ┌────────────────────────┐         │
        │      │  Fraud rule engine     │         │
        │      │  6 weighted rules      │         │
        │      └───────────┬────────────┘         │
        │                  ▼                      │
        │   risk score 0-100 → severity band      │
        │                  ▼                      │
        │   medium+ ⇒ raise alert (in-memory Map) │
        │                  ▼                      │
        │   POST /alerts/:id/escalate             │
        │        → aiops-incidents channel        │
        └─────────────────────────────────────────┘
```

### Fraud rule engine

Each incoming transaction is evaluated against every rule. Firing rules contribute
their weight to a cumulative risk score, capped at 100.

| Rule ID | Weight | Fires when |
|---|---|---|
| `HIGH_AMOUNT` | 35 | Transaction amount exceeds 5000 |
| `VELOCITY` | 25 | 3+ transactions from the same account within 60s |
| `GEO_MISMATCH` | 20 | Billing country differs from origin country |
| `HIGH_RISK_COUNTRY` | 15 | Origin country is on the elevated-risk list |
| `NEW_DEVICE` | 10 | Device has not been seen before for this account |
| `ODD_HOUR` | 5 | Transaction occurs between 01:00–05:00 UTC |

### Severity classification

| Risk score | Severity | Alert raised? |
|---|---|---|
| 80–100 | `critical` | ✅ |
| 60–79 | `high` | ✅ |
| 35–59 | `medium` | ✅ |
| 0–34 | `low` | ❌ (scored only) |

### Alert lifecycle

```
open ──escalate──▶ escalated ──resolve──▶ resolved
  └──────────────resolve─────────────────────▲
```

Escalating an already-resolved alert returns `409 ALERT_ALREADY_RESOLVED`.

---

## API Reference

### Observability

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness — status, version, uptime |
| `GET` | `/ready` | Readiness — rules loaded, open alert count |
| `GET` | `/metrics` | Counters and gauges (JSON) |

These three endpoints bypass both the rate limiter and API key auth.

### Fraud scoring

| Method | Path | Description |
|---|---|---|
| `GET` | `/rules` | List the active rule set with weights |
| `POST` | `/transactions/score` | Score a transaction, raise an alert if medium+ |
| `GET` | `/transactions/:id` | Fetch a previously scored transaction |

**`POST /transactions/score`**

```jsonc
// request
{
  "accountId": "acct-1001",     // required, string
  "amount": 9500,               // required, positive number
  "currency": "USD",            // optional, default "USD"
  "originCountry": "NG",        // optional, ISO-3166 alpha-2
  "billingCountry": "US",       // optional, ISO-3166 alpha-2
  "deviceId": "dev-xyz",        // optional
  "occurredAt": "2026-08-12T03:14:00Z"  // optional, defaults to now
}
```

```jsonc
// 201 response
{
  "transactionId": "…",
  "riskScore": 80,
  "severity": "critical",
  "triggeredRules": [
    { "ruleId": "HIGH_AMOUNT",       "weight": 35, "reason": "amount above 5000" },
    { "ruleId": "GEO_MISMATCH",      "weight": 20, "reason": "billing US != origin NG" },
    { "ruleId": "HIGH_RISK_COUNTRY", "weight": 15, "reason": "origin NG is high risk" },
    { "ruleId": "NEW_DEVICE",        "weight": 10, "reason": "unseen device dev-xyz" }
  ],
  "alertId": "…",
  "requestId": "…"
}
```

### Alerts

| Method | Path | Description |
|---|---|---|
| `GET` | `/alerts` | List alerts, sorted by risk score descending |
| `GET` | `/alerts/:id` | Fetch a single alert |
| `POST` | `/alerts/:id/escalate` | Route the alert to an incident channel |
| `POST` | `/alerts/:id/resolve` | Close the alert with a resolution |

`GET /alerts` query params: `severity`, `status`, `accountId`, `limit` (max 200).

`POST /alerts/:id/escalate` body: `{ "channel": "aiops-incidents" }` (optional).

`POST /alerts/:id/resolve` body: `{ "resolution": "confirmed_fraud" }` (optional,
defaults to `confirmed_legitimate`).

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP listen port |
| `NODE_ENV` | `development` | Runtime environment |
| `LOG_LEVEL` | `info` | One of `error`, `warn`, `info`, `debug` |
| `SERVICE_NAME` | `rca-alert-fraud-detection-service` | Reported in logs and `/health` |
| `SERVICE_VERSION` | `1.0.0` | Reported in logs and `/health` |
| `API_KEY` | *(unset)* | When set, all non-health routes require `X-Api-Key` |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Fixed rate-limit window, milliseconds |
| `RATE_LIMIT_MAX` | `100` | Max requests per window per client IP |
| `FAILURE_RATE` | `0.05` | Injected downstream failure probability (demo realism) |

---

## Error Responses

| Status | Code | Meaning |
|---|---|---|
| `400` | — | Missing `accountId` or non-positive `amount` |
| `401` | `UNAUTHORIZED` | `API_KEY` is set and `X-Api-Key` did not match |
| `404` | `ALERT_NOT_FOUND` / `TRANSACTION_NOT_FOUND` / `NOT_FOUND` | Unknown resource |
| `409` | `ALERT_ALREADY_RESOLVED` | Cannot escalate a resolved alert |
| `429` | `RATE_LIMIT_EXCEEDED` | Rate limit tripped |
| `503` | `SCORING_ENGINE_TIMEOUT` | Injected demo failure |

Every response carries an `X-Request-Id` header, echoed as `requestId` in JSON bodies.

---

## Testing

```bash
node --test test/service.test.js
```

Tests use the Node built-in `node:test` runner. `FAILURE_RATE` is forced to `0`
in the test suite so injected failures do not cause flakes.

---

## CI/CD

`.github/workflows/ci.yml` runs on every push and PR to `main`:

1. **Build & Package** — checkout, Node 18, `npm ci`, `npm run build`
2. **Deploy to prod-east** — gated on the `prod-east` environment, `main` pushes only

## Service Registry

Registered in the Atlassian Service Registry (JSR) on the `lumosss` tenant with
`serviceTier: 3` and linked to this repository.
