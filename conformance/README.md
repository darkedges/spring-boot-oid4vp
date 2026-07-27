# Automated conformance suite runs

`run_conformance.py` automates the manual workflow described in the top-level `README.md`
("Extra relying parties for conformance testing" / "Invoking a Wallet"): bring the demo
Verifier up under the `cloudflare` profile, create a test plan on your conformance-suite
instance and start one of its test modules, wire its exported mock-Wallet
`authorization_endpoint` into the right registration, trigger the exchange, and report
pass/fail.

It targets a **self-hosted** instance of
[`gitlab.com/openid/conformance-suite`](https://gitlab.com/openid/conformance-suite),
confirmed against a live dev-mode instance (`docker-compose-dev.yml`, browsable at
`https://localhost.emobix.co.uk:8443/`).

## Usage

```bash
CONFORMANCE_SERVER="https://localhost.emobix.co.uk:8443/" \
  ./conformance/run_conformance.py \
    --config conformance/zkp-iso-mdl-test-config.json \
    --plan-name oid4vp-1final-verifier-test-plan \
    --variant '{"credential_format":"iso_mdl","client_id_prefix":"x509_hash","request_method":"request_uri_signed","vp_profile":"haip","response_mode":"direct_post.jwt"}' \
    --module oid4vp-1final-verifier-happy-flow \
    --alias conformancemdoc
```

- `--alias` must be one of `conformance` (`dc+sd-jwt`), `conformancemdoc` (`mso_mdoc`), or
  `conformancecode` (Authorization Code Grant) — matching the demo Verifier registration the
  plan is meant to drive (see the top-level README's "Extra relying parties" section for what
  each one is configured for).
- `--plan-name` is the plan identifier as shown in your suite's plan catalogue (ends in
  `-test-plan`, e.g. `oid4vp-1final-verifier-test-plan`) — not the name of an individual test
  module within it.
- `--variant` is required for plans whose modules vary by axis (credential format, client ID
  prefix, request method, VP profile, response mode, ...) — the suite will 400 with a
  `TestModule '...' requires a value for variant '...'` error naming the missing axis if you
  omit one it needs. **Discover the valid axes/values for a plan** by querying the suite
  directly:
  ```bash
  curl -sk https://localhost.emobix.co.uk:8443/api/runner/available \
    | python3 -c 'import json,sys; [print(json.dumps(m["variants"], indent=2)) for m in json.load(sys.stdin) if m["testName"]=="<module-name>"]'
  ```
  Some combinations are mutually exclusive (e.g. `client_id_prefix: x509_hash` only pairs with
  `request_method: request_uri_signed`, never `url_query`) — each variant's `notApplicableWhen`
  in that output spells out the constraint.
- `--module` picks which of the plan's test modules to actually run (a plan lists several,
  e.g. `oid4vp-1final-verifier-happy-flow`, `oid4vp-1final-verifier-request-uri-method-post`,
  `oid4vp-1final-verifier-invalid-session-transcript`); defaults to the first one listed.
- Pass `--no-compose` if the stack is already running and you don't want it restarted.
- Pass `--with-tunnel` only if your Cloudflare tunnel is itself managed via
  `docker-compose.tunnel.yml`. If it's a separately managed long-lived tunnel (e.g. a
  Kubernetes `cloudflared` deployment), leave this off — the default compose invocation is
  just `docker-compose.yml` + `docker-compose.cloudflare.yml`.

### Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `CONFORMANCE_SERVER` | yes | Base URL of your self-hosted conformance-suite instance |
| `CONFORMANCE_TOKEN` | no | Bearer API token, if your instance requires one (omit for a dev-mode instance) |
| `CONFORMANCE_INSECURE_TLS` | no | Set to `1` to skip TLS verification (self-signed suite certs) |

## How plan/module creation actually works

Confirmed against a live instance — this differs from an earlier assumption in this script's
first draft:

1. `POST /api/plan` **registers a plan** (given your config + variant) and returns its `id`
   plus the **names** of its constituent test modules. It does not instantiate or start any of
   them, and the response has no per-module `id` yet.
2. `POST /api/runner?test=<name>&plan=<id>` **instantiates and starts one specific module**.
   For an RP/Verifier test like these, it comes up already in `WAITING` state — no separate
   start call needed. The response's `id` is the module id used for all subsequent polling, and
   its `url` is the module's own base URL.
3. The mock-Wallet endpoint the Verifier under test should be pointed at is always
   `<module url>/authorize` — the suite exposes a small OIDC-style discovery surface under each
   running module's base URL (`/authorize`, `/token`, `/jwks`, ...), confirmed by inspecting a
   live module's `GET /api/log/{id}` entries.

## What it doesn't do

- Tear down the stack afterward (matches the manual workflow — that stays a separate,
  explicit `docker compose down` when you're done).
- Run inside CI. This drives your own long-lived deployment, so it's meant to be run on demand
  from a machine that can reach both your conformance-suite instance and can restart that
  deployment's containers.
