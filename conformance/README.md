# Automated conformance suite runs

`run_conformance.py` automates the manual workflow described in the top-level `README.md`
("Extra relying parties for conformance testing" / "Invoking a Wallet"): bring the demo
Verifier up under the `cloudflare`+`tunnel` profiles, create and start a test plan on your
conformance-suite instance, wire its exported mock-Wallet `authorization_endpoint` into the
right registration, trigger the exchange, and report pass/fail.

It targets a **self-hosted** instance of
[`gitlab.com/openid/conformance-suite`](https://gitlab.com/openid/conformance-suite) — the
HTTP calls it makes mirror that project's own reference automation
(`scripts/conformance.py` / `scripts/run-test-plan.py`).

## Usage

```bash
CONFORMANCE_SERVER="https://your-conformance-instance.example/" \
  ./conformance/run_conformance.py \
    --config conformance/zkp-iso-mdl-test-config.json \
    --plan-name oid4vp-1final-verifier-happy-path \
    --alias conformancemdoc
```

- `--alias` must be one of `conformance` (`dc+sd-jwt`), `conformancemdoc` (`mso_mdoc`), or
  `conformancecode` (Authorization Code Grant) — matching the demo Verifier registration the
  plan is meant to drive (see the top-level README's "Extra relying parties" section for what
  each one is configured for).
- `--plan-name` is the plan identifier as shown in your suite's plan catalogue, not a
  free-form label — check `GET <server>/api/plan`/the suite UI's "Create Test Plan" page for
  the exact name for the config you're using.
- Pass `--no-compose` if the stack is already running (it will still restart it to pick up
  the freshly exported `authorization_endpoint` unless you also skip that with `--no-compose`
  — see the script's `--help`).

### Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `CONFORMANCE_SERVER` | yes | Base URL of your self-hosted conformance-suite instance |
| `CONFORMANCE_TOKEN` | no | Bearer API token, if your instance requires one |
| `CONFORMANCE_INSECURE_TLS` | no | Set to `1` to skip TLS verification (self-signed suite certs) |

## Known unknowns — read before your first run

This was written from the conformance-suite's public API surface (confirmed: `POST
/api/plan`, `POST /api/runner/{id}`, `GET /api/runner/{id}/wait-state`, `GET
/api/info/{id}`, `GET /api/log/{id}`, all bearer-token-authenticated) rather than against a
live instance, since automating this was scoped to *your* self-hosted deployment. Two things
are very likely to need a small correction on the first real run:

1. **`--export-path`** (default `exposed.authorization_endpoint`) — the dot-path into
   `GET /api/info/{moduleId}`'s JSON body where the mock-Wallet `authorization_endpoint` the
   suite exposes actually lives. If it's wrong, the script prints the full module-info JSON
   to stderr before failing — find the real field there and pass the correct
   `--export-path`.
2. **Module auto-start behaviour** — the script assumes a freshly created plan's first module
   may need an explicit `POST /api/runner/{id}` to start (it checks `status` first and only
   calls start if the module isn't already `WAITING`/`RUNNING`). If your instance's plans
   auto-start on creation, this is a harmless no-op; if a module needs different handling
   (e.g. it isn't the automation-friendly kind at all), you'll see that surface as a
   `wait_for_state` timeout.

Once you've confirmed the right `--export-path` for a given plan type, it's stable across
runs of the same plan — you won't need to rediscover it every time.

## What it doesn't do

- Tear down the stack afterward (matches the manual workflow — that stays a separate,
  explicit `docker compose down` when you're done).
- Run inside CI. This drives your own long-lived Cloudflare-tunnelled deployment, so it's
  meant to be run on demand from a machine that can reach both your conformance-suite
  instance and can restart that deployment's containers.
