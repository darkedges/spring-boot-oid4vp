# OpenID4VP on Spring Security

A Java implementation of [OpenID for Verifiable Presentations 1.1](docs/1.1/openid-4-verifiable-presentations-1_1.md),
integrated with Spring Security 7.1.0 / Spring Boot 4.1.0.

## Modules

| Module | Purpose |
|---|---|
| `oid4vp-core` | Format-agnostic protocol model: DCQL, Claims Path Pointer, Client Identifier Prefix, Authorization Request/Response |
| `oid4vp-test-fixtures` | Test fixtures sourced directly from `docs/1.1/examples/` |
| `oid4vp-format-sdjwt-vc` | `dc+sd-jwt` (SD-JWT VC) format: parsing, digest verification, Key Binding JWT, presentation building |
| `oid4vp-format-jwt-vc-json` | `jwt_vc_json` format verifier |
| `oid4vp-verifier-core` | Verifier-side response validation, response decryption (JWE), Request Object signing |
| `oid4vp-wallet-core` | Wallet-side DCQL evaluation → `vp_token` orchestration |
| `oid4vp-spring-security` | Spring Security integration: `AuthenticationProvider`, `direct_post`/DC API filters, `Oid4vpLoginConfigurer` DSL |
| `oid4vp-spring-boot-autoconfigure` | `oid4vp.verifier.*` properties and default beans |
| `oid4vp-demo-wallet` | Runnable demo Wallet app |
| `oid4vp-demo-verifier` | Runnable demo Verifier app |

## Prerequisites

- **Java 21** and **Maven 3.9+**. If you don't have them installed system-wide, grab a local copy and point your shell at it — nothing here needs root:

  ```bash
  mkdir -p ~/.local/opt && cd ~/.local/opt
  curl -sL "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse" -o jdk21.tar.gz
  tar xzf jdk21.tar.gz && rm jdk21.tar.gz
  curl -sL "https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz" -o maven.tar.gz
  tar xzf maven.tar.gz && rm maven.tar.gz

  export JAVA_HOME="$HOME/.local/opt/jdk-21.0.11+10"   # match the extracted directory name
  export PATH="$JAVA_HOME/bin:$HOME/.local/opt/apache-maven-3.9.9/bin:$PATH"
  ```

## Build

```bash
mvn install -DskipTests   # or drop -DskipTests to also run the ~106 unit tests
```

## Running the demo

The demo is two independent Spring Boot apps that talk to each other over plain HTTP — no browser or
real Wallet app required, everything is drivable with `curl`.

| App | Port | Role |
|---|---|---|
| `oid4vp-demo-wallet` | `8081` | Self-issues one SD-JWT VC credential at startup and can present it to a Verifier on request |
| `oid4vp-demo-verifier` | `8090` | Requests a presentation, verifies it, and gates `/profile` behind a valid one |

### In a browser

`oid4vp-demo-verifier` serves a small static page at `http://localhost:8090/` — "ZKP Employee
Verification" — with a **Sign in with Wallet** button. It tells the same story `demo.sh` does, but as an
End-User would experience it: click the button, the page calls the demo Wallet's `/present` endpoint
cross-origin (CORS is opened up on the Wallet for `http://localhost:8090` — see `@CrossOrigin` on
`WalletController.present`), the Wallet builds and submits the presentation, and the browser is redirected
back to `/` — now signed in, showing "Welcome, Jane Demo".

This relies on the library's same-device `response_code`/`redirect_uri` handoff
(`Oid4vpTransactionResultFilter`) redirecting to `/` on success rather than returning its default bare
`{}` JSON ack — configured via `.sameDeviceResultRedirectUri("/")` in `SecurityConfig`.

The page also can't hardcode which URL to hand the Wallet for fetching the Authorization Request:
bare-metal that's the page's own origin (`http://localhost:8090`), but under docker-compose the Wallet's
container can't reach that — its `localhost` is itself, not the Verifier. `GET /demo-config`
(`DemoConfigController`, backed by `demo.verifier-base-url-for-wallet`, overridden in
`application-docker.yml` to the compose service name) tells the page the right URL for whichever mode
it's running in.

Start both apps (`docker compose up --build`, or bare-metal per below) and open
[http://localhost:8090](http://localhost:8090).

### Quickest path: `demo.sh`

```bash
mvn install -DskipTests   # build the jars first — the Dockerfiles just package them, not a full Maven build
./demo.sh
```

This starts both apps with `docker compose up --build`, waits for them to be ready, then walks through
the whole flow (issue request → Wallet presents → Verifier verifies → same-device handoff → protected
`/profile`), printing each `curl` call and its response and pausing after each step so you can read it.
At the end it offers to `docker compose down` for you.

If you'd rather run the apps yourself (no Docker) — e.g. via `java -jar` as below, or from your IDE —
use `./demo.sh --no-docker`, which skips the `docker compose` step and drives the same walkthrough
against whatever is already listening on `localhost:8081`/`8090`.

### Manual walkthrough

#### 1. Start both apps

In two separate terminals (or backgrounded, as below):

```bash
java -jar oid4vp-demo-wallet/target/oid4vp-demo-wallet.jar
java -jar oid4vp-demo-verifier/target/oid4vp-demo-verifier.jar
```

Wait for both to log `Started Demo*Application`.

#### 2. Drive the flow with curl

**Fetch an Authorization Request from the Verifier:**

```bash
curl -s http://localhost:8090/oid4vp/authorize/demo | python3 -m json.tool
```

Returns the request JSON (`nonce`, `state`, `dcql_query`, `response_uri`, plus a `transaction_id` used
for the same-device handoff below).

**Tell the Wallet to fetch that request, build a presentation, and POST it to the Verifier:**

```bash
curl -s -X POST http://localhost:8081/present \
  -H "Content-Type: application/json" \
  -d '{"verifierAuthorizeUrl":"http://localhost:8090/oid4vp/authorize/demo"}'
```

On success this returns `{"redirect_uri": "http://localhost:8090/oid4vp/result/<txn>?response_code=..."}`
— the same `response_code`/`redirect_uri` same-device handoff a real Wallet would use to hand control
back to the Verifier's frontend.

**Follow that redirect (with a cookie jar, to pick up the session) and then access the protected page:**

```bash
curl -c cookies.txt "http://localhost:8090/oid4vp/result/<txn>?response_code=<code>"   # paste from above
curl -b cookies.txt http://localhost:8090/profile
# => {"authenticated":true,"given_name":"Jane","family_name":"Demo"}

curl http://localhost:8090/profile   # no cookie
# => 403
```

#### 3. One-liner

```bash
TXN_URI=$(curl -s -X POST http://localhost:8081/present \
  -H "Content-Type: application/json" \
  -d '{"verifierAuthorizeUrl":"http://localhost:8090/oid4vp/authorize/demo"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["redirect_uri"])')
curl -c /tmp/cookies.txt "$TXN_URI" && curl -b /tmp/cookies.txt http://localhost:8090/profile
```

## Configuring the demo

Both apps are configured via `src/main/resources/application.yml`.

**`oid4vp-demo-verifier`** (`oid4vp.verifier.relying-party.demo.*`, bound by `oid4vp-spring-boot-autoconfigure`):

- `client-id` / `response-uri` — must resolve to a path that matches
  `Oid4vpLoginConfigurer`'s response endpoint pattern. The demo uses the library's default
  (`/login/oid4vp/direct-post/{registrationId}`); if you change `response-uri`, either keep the
  `{registrationId}` segment matching a `.responseUriPattern(...)` you configure in `SecurityConfig`, or
  keep using the default.
- `dcql-query` — raw JSON (the DCQL model doesn't bind cleanly to YAML). Must reference a
  `vct_values` entry the Wallet actually issues (`DemoConstants.VCT` in `oid4vp-demo-wallet`).
- `demo.wallet-base-url` — where the Verifier fetches the Wallet's issuer JWKS from
  (`SecurityConfig.issuerKeyResolver`).

**`oid4vp-demo-wallet`**: no external config — the credential (claims, `vct`, issuer/holder keys) is
built in `DemoCredentialConfig` at startup. Change the claims or `vct` there (and keep
`oid4vp-demo-verifier`'s `dcql-query` in sync) to try a different scenario.

Both apps' ports are set via `server.port`.

### Docker profile

`oid4vp-demo-verifier/src/main/resources/application-docker.yml` (activated by `SPRING_PROFILES_ACTIVE=docker`
in `docker-compose.yml`) overrides `demo.wallet-base-url`, `client-id`, and `response-uri` to use the
docker-compose service names (`wallet`, `verifier`) instead of `localhost`, since those URLs are called
container-to-container. `demo.same-device-result-base-uri` is deliberately **not** overridden — it's
followed by the End-User's browser (or `demo.sh`, running on your host), which reaches the Verifier via
its published port on `localhost` either way. If you rename the services in `docker-compose.yml`, update
`application-docker.yml` to match.

### Hosting behind Cloudflare

To expose the demo publicly — e.g. Wallet on `wallet.zkp.au`, Verifier on `verify.irving.au` — activate the
**`cloudflare`** Spring profile instead of (not in addition to) `docker`:

```bash
docker compose -f docker-compose.yml -f docker-compose.cloudflare.yml up -d --build
```

`application-cloudflare.yml` in each module sets every URL the two apps use — including the ones they use
to call *each other* — to the public HTTPS domain, rather than a docker-compose-internal hostname. This is
deliberate: the pairing is meant to work as if Wallet and Verifier are two independently-hosted parties on
separate domains, not just two containers on one private network, so nothing round-trips through a
`localhost`/service-name shortcut that only exists locally. If you're using different domains, edit both
`application-cloudflare.yml` files (and `docker-compose.cloudflare.yml`'s comment) to match.

You still need to actually get traffic to the containers — this repo doesn't include a Cloudflare Tunnel
config. Typically that means running `cloudflared` (as a sidecar container or on the host) with two
ingress rules, one per hostname, pointing at `localhost:8081` (Wallet) and `localhost:8090` (Verifier).

Two properties matter here that are easy to conflate: `demo.wallet-base-url` is fetched **server-side** by
the Verifier (`IssuerKeyResolver` hitting `/issuer-jwks`), while `demo.wallet-base-url-for-browser` is
fetched **by the browser** itself (the "Sign in with Wallet" page calling `/present` cross-origin) — under
plain `docker` these differ (container-internal vs. published-port), so they're separate properties on
purpose; don't merge them back into one.

## Notes

- The Wallet self-issuing its own credential (`DemoCredentialConfig`) is a demo-only shortcut —
  credential *issuance* is a separate protocol (OpenID for Verifiable Credential Issuance) outside this
  project's scope. A real Wallet receives credentials from a real Issuer.
- `IssuerKeyResolver` fetching the issuer's key straight from the Wallet's own `/issuer-jwks` endpoint is
  also a demo-only simplification (there's no real trust relationship being checked). A real Verifier
  resolves issuer trust through whatever framework it's deployed under.
