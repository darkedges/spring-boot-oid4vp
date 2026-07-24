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

`oid4vp-demo-verifier` serves a small static page at `http://localhost:8090/` — "Acme Corp Employee
Verification" — with a **Sign in with Wallet** button. It tells the same story `demo.sh` does, but as an
End-User would experience it: click the button, the page calls the demo Wallet's `/present` endpoint
cross-origin (CORS is opened up on the Wallet for `http://localhost:8090` — see `@CrossOrigin` on
`WalletController.present`), the Wallet builds and submits the presentation, and the browser is redirected
back to `/` — now signed in, showing "Welcome, Jane Demo".

The "Acme Corp" name in the page's copy comes from `demo.employer-name` (`DemoConfigController`, exposed
via `GET /demo-config`) — override it with the `DEMO_EMPLOYER_NAME` environment variable (Spring Boot
relaxed-binds env vars to properties) to rebrand without touching HTML. Already wired into
`docker-compose.yml` with a default of `Acme Corp`; set it in your shell or a `.env` file before
`docker compose up`.

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

You still need to actually get traffic to the containers. `docker-compose.tunnel.yml` layers on a
`cloudflared` connector for this — see its header comment for the one-time dashboard setup (create a
tunnel, add the two Public Hostname routes, copy the token):

```bash
CLOUDFLARE_TUNNEL_TOKEN="<token from the dashboard>" docker compose \
  -f docker-compose.yml -f docker-compose.cloudflare.yml -f docker-compose.tunnel.yml up -d --build
```

One tunnel/token covers both `verify.irving.au` and `wallet.zkp.au` as long as both domains are on the
same Cloudflare account — the tunnel's Public Hostname routes point at the compose service names
(`verifier:8090`, `wallet:8081`), reached over the compose network like any other container-to-container
call in this stack, not `localhost`.

Two properties matter here that are easy to conflate: `demo.wallet-base-url` is fetched **server-side** by
the Verifier (`IssuerKeyResolver` hitting `/issuer-jwks`), while `demo.wallet-base-url-for-browser` is
fetched **by the browser** itself (the "Sign in with Wallet" page calling `/present` cross-origin) — under
plain `docker` these differ (container-internal vs. published-port), so they're separate properties on
purpose; don't merge them back into one.

### Signed Authorization Requests (`request_uri`)

`GET /oid4vp/request/{registrationId}` (e.g. `/oid4vp/request/demo`) hosts a **signed** Request Object —
`application/oauth-authz-req+jwt`, per RFC9101/OpenID4VP's `request_uri` mechanism — alongside the
existing plain-JSON `/oid4vp/authorize/demo` (which the demo Wallet keeps using unchanged; nothing here
affects that path).

This exists for talking to a real/conformant Wallet — e.g. the OpenID Foundation's conformance suite, or
anything that won't just trust an unsigned inline request the way the demo Wallet does. Signing requires
switching the relying-party's `client-id` from `redirect_uri:...` to `x509_san_dns:<hostname>`: per spec,
"implementations requiring signed requests cannot use the `redirect_uri` Client Identifier Prefix" (there's
no key for the Wallet to verify against). `x509_san_dns` instead carries the signer's certificate chain
directly in the JWS header's `x5c` field, so the Wallet verifies the signature against the leaf cert
without needing to resolve a key some other way.

The signing key is `oid4vp-demo-verifier/src/main/resources/demo-verifier-signing-key.p12` — a self-signed
EC (P-256) cert generated once via `openssl` (see `DemoVerifierSigningKeyConfig`), with SANs covering
`localhost`, `verifier` (the docker-compose service name), and `verify.irving.au` (the Cloudflare domain),
matching whichever `client-id` each profile uses. It's demo-only, not a pattern for a real deployment,
which would use a certificate issued by a CA the relying Wallets actually trust. Loaded via plain
`java.security.KeyStore` rather than Nimbus's `ECKey.load(KeyStore, ...)` convenience method, which pulls
in BouncyCastle internally — this project has no BC dependency and it wasn't worth adding one just for
that.

If you regenerate the cert for different hostnames, keep the `client-id` values in `application.yml` /
`application-docker.yml` / `application-cloudflare.yml` in sync with its SANs.

### Extra relying parties for conformance testing (`conformance`, `conformancecode`)

`application-cloudflare.yml` defines **two extra** relying-party registrations alongside `demo`, each
isolated so the local browser demo (`demo`, plain `direct_post`) is never affected:

- **`conformance`** — `response_mode: direct_post.jwt` (encrypted response). Nothing in
  `oid4vp-wallet-core` can encrypt a response, so our own demo Wallet only ever speaks plain
  `direct_post`; this registration has its own `client-metadata` carrying a static demo EC encryption key
  (`DemoVerifierEncryptionKeyConfig` — its public half is embedded there, matching the checked-in private
  key used to decrypt).
- **`conformancecode`** — `response_type=code` (the OAuth 2.0 Authorization Code Grant, PKCE-protected).
  Architecturally inverted from everything else here: per spec, "the VP Token is provided in the Token
  Response", so *our Verifier* acts as the OAuth client — it sends the initial request (via the same
  signed `request_uri` hosting), gets a `code` back at `redirect-uri` (`GET /oid4vp/callback/{registrationId}`,
  `Oid4vpAuthorizationCodeCallbackFilter`), then exchanges it at `wallet-token-endpoint` for a Token
  Response containing `vp_token` — validated through the exact same code path as `direct_post`
  (`Oid4vpAuthorizationResponseAuthenticationProvider`; the token type it consumes is fully
  transport-agnostic, so no library code needed changing there). `redirect-uri` alone is the code-flow
  toggle on a registration; `wallet-token-endpoint` is independently optional — it's fine for it to stay
  unset until a real test run supplies one, hosting/invoking still works either way, only the eventual
  code exchange needs it and fails with a clear message if it's still missing.

If a test plan wants plain `direct_post` instead of either, `demo` already does that.

### Invoking a Wallet (`GET /oid4vp/invoke/{registrationId}`)

Opening `/oid4vp/invoke/conformance` (or `/oid4vp/invoke/conformancecode`) in a browser redirects to a
Wallet's `authorization_endpoint` with `client_id`/`request_uri` attached — "in the same way a web-based
wallet would be invoked", which is exactly how the OpenID Foundation conformance suite documents inviting
its own Verifier test plans. This is the missing piece for actually driving a conformance test run: create
a Verifier test plan in the suite (DCQL, `dc+sd-jwt`, `x509_san_dns`, and whichever `response_type`/
`response_mode` it asks for — `direct_post` maps to `demo`, `direct_post.jwt` to `conformance`, `code` to
`conformancecode`), start it, copy the `authorization_endpoint` URL (and, for the `code` flow, the token
endpoint URL too) from its "Exported Values" once it's `WAITING`, and set:

```bash
CONFORMANCE_WALLET_AUTHORIZATION_ENDPOINT="<paste the exported URL>" docker compose \
  -f docker-compose.yml -f docker-compose.cloudflare.yml -f docker-compose.tunnel.yml up -d --build
# for the code flow instead:
CONFORMANCE_CODE_WALLET_AUTHORIZATION_ENDPOINT="<exported authorization_endpoint>" \
  CONFORMANCE_CODE_WALLET_TOKEN_ENDPOINT="<exported token_endpoint>" docker compose \
  -f docker-compose.yml -f docker-compose.cloudflare.yml -f docker-compose.tunnel.yml up -d --build
```

**Must be the `cloudflare` profile (plus the tunnel), not plain `docker`** — the conformance suite runs on
its own remote server and fetches `request_uri` itself, so that URL has to be something *its* server can
reach. Under plain `docker`, `demo.request-uri-base` resolves to `http://localhost:8090`, which is only
ever reachable from your own machine; the suite gets a plain connection-refused trying to fetch it. Under
`cloudflare`, it resolves to `https://verify.irving.au/oid4vp/request`, which the tunnel makes real. (These
env vars are deliberately wired into `docker-compose.cloudflare.yml`, not the base file — `conformance`/
`conformancecode` only exist under this profile at all; setting `CONFORMANCE_WALLET_AUTHORIZATION_ENDPOINT`
under plain `docker` would make Spring Boot infer a broken partial `conformance` registration from that one
property alone and fail to start. `conformancecode`'s two env vars don't have that failure mode — see
above — but are still cloudflare-only since the registration itself only exists there.)

Then open `https://verify.irving.au/oid4vp/invoke/conformance` (or `.../conformancecode`) — not
`localhost`, same reasoning — in a browser. Unset, these env vars default to empty and the invoke endpoint
returns `501` — there's deliberately no way to pass a redirect target as a request parameter instead,
since that would be an open redirect. Each relying-party registration configures its own fixed
`wallet-authorization-endpoint` (`Oid4vpRelyingPartyRegistration.walletAuthorizationEndpoint`); nothing
here lets a caller redirect anywhere they choose.

## Notes

- The Wallet self-issuing its own credential (`DemoCredentialConfig`) is a demo-only shortcut —
  credential *issuance* is a separate protocol (OpenID for Verifiable Credential Issuance) outside this
  project's scope. A real Wallet receives credentials from a real Issuer.
- `IssuerKeyResolver` resolves the issuer's key two ways, both demo-only simplifications with no real trust
  relationship being checked: first from the credential's own embedded `x5c` certificate chain (trusting
  a self-signed leaf certificate outright, no CA/chain validation — this is what lets the demo Verifier
  accept credentials from external Wallets/issuers, such as those used by the OpenID Foundation
  conformance suite), falling back to fetching the issuer's key straight from the Wallet's own
  `/issuer-jwks` endpoint for credentials that carry no `x5c` (only the demo Wallet's own self-issued
  credential, via `DemoCredentialConfig`). A real Verifier resolves issuer trust through whatever
  framework it's deployed under.
- All three registrations (`demo`, `conformance`, `conformancecode`) use the `x509_hash` Client Identifier
  Prefix — `client-id: "x509_hash:<base64url(sha256(DER of demo-verifier-signing-key.p12's leaf cert))>"`
  — rather than `x509_san_dns`, since OpenID4VC HAIP (High Assurance Interoperability Profile) forbids
  `x509_san_dns`/`verifier_attestation` outright and mandates `x509_hash`. `ExpectedAudienceResolver`
  (`oid4vp-core`) still handles `x509_san_dns` correctly for any consumer that isn't targeting HAIP — this
  demo just doesn't exercise that branch anymore. The demo Wallet's `/present` flow fetches an *unsigned*
  convenience JSON authorization request (`AuthorizeController`) that never carries the signing
  certificate, so `AuthorizeController` still precomputes the expected response audience into a bespoke
  `expected_response_audience` field (safe only because that whole JSON endpoint is demo-only) — with
  `x509_hash` as the client-id this now just mirrors `client_id` verbatim, but the mechanism stays generic.
- `demo-verifier-signing-key.p12`'s leaf certificate is issued by a throwaway demo CA (also checked into
  the keystore) rather than being self-signed itself — HAIP-conformant Wallets reject a self-signed leaf.
  Regenerated via `keytool` (CA keypair → leaf keypair/CSR → CA signs the CSR → both certs imported back
  into the leaf's keystore entry); if regenerated again, every registration's `client-id` above must be
  recomputed to match the new leaf's hash.
- The signed Request Object always carries `aud: "https://self-issued.me/v2"` (`RequestObjectSigner`) —
  OpenID4VP's Static Discovery convention, since this project never does Dynamic Discovery (resolving a
  Wallet's own issuer metadata). Nonce/state/transaction-id are 256-bit random tokens
  (`Oid4vpAuthorizationRequestService`), comfortably above the spec's 128-bit floor. `conformance`'s
  `client-metadata` declares both `A128GCM` and `A256GCM` under `encrypted_response_enc_values_supported`,
  as HAIP requires — Nimbus's `ECDHDecrypter` already handles either transparently, so this was a
  metadata-only change.
