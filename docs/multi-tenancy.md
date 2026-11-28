# Multi-tenancy (`oid4vc-tenancy`)

One issuer or verifier deployment can serve many tenants. Each tenant is an AuthStack environment that has enabled credential
issuance or verification, and has its own identifier, keys, settings and state. The module is shared by this verifier and the OID4VCI
issuer. It is off unless `oid4vc.tenancy.enabled=true`, so a single-tenant deployment is unchanged.

## How a request finds its tenant

The resolver tries these, in order:

| Order | Request | Tenant | Its identifier (base URL) |
|---|---|---|---|
| 1 | `https://bank.issuer.zkp.au/token` | the slug `bank` (platform subdomain) | `https://bank.issuer.zkp.au` |
| 2 | `https://issuer.bank.example/token` | the environment that verified this custom domain in AuthStack | `https://issuer.bank.example` |
| 3 | `https://issuer.zkp.au/t/bank/token` | the slug `bank` (path) | `https://issuer.zkp.au/t/bank` |
| 4 | `https://issuer.zkp.au/token` | the deployment's default tenant, if it has one | `https://issuer.zkp.au` |

Anything else is answered with 404. So is a disabled tenant.

**Paths.**
- For path routing, the filter removes `/t/<slug>`, so controllers and security rules keep their single-tenant paths: `/t/bank/token`
  is handled as `/token`.
- The metadata of a path tenant is at the inserted well-known URL (RFC 8414 §3.1), `/.well-known/<name>/t/<slug>`, which is handled
  as `/.well-known/<name>`.
- `TenantContext.wellKnown(name)` builds that URL.
- **Platform paths** (`oid4vc.tenancy.platform-paths`: the admin API, `/actuator/**`, `/error`) are served on any host without a tenant.

**Hosts.**
- **A tenant never names its own hosts.** Custom domains come only from AuthStack, which links one to an environment once its owner
  has proved control (a DNS TXT challenge) and its certificate is issued. AuthStack is asked through
  `GET /api/platform/domains?purpose=issuer|verifier`, with the platform worker's client credentials. The answer is cached for 30
  seconds, and an unknown host triggers at most one early refresh every 5 seconds.
- **`X-Forwarded-Host`** counts only when `trust-forwarded-headers` is on, and only if it names one of the deployment's hosts. A client
  can't choose a tenant by sending it.

**In application code.**
- `TenantContext.require(request)`: the tenant, `baseUrl()`, `url("/token")` and `wellKnown(...)`.
- `TenantContext.current()`: the same, where no request is at hand.

## Keys

`TenantKeyService` gives each tenant its own EC P-256 keys, one set per purpose: `issuer-signing`, `mdoc` and `request-object`.
- **Created on first use.** The private key never leaves the service.
- **Encrypted at rest** with AES-256-GCM under `oid4vc.tenancy.keys.encryption-key` (`TENANT_KEY_ENCRYPTION_KEY`, base64 of 32 random
  bytes). Each value is bound to its tenant and key id. **Back the key up: losing it loses every tenant's keys.**
- **Certified by the deployment's CA** (`keys.ca-keystore`, a PKCS#12 keystore entry with its private key). The certificate is the
  `x5c` of SD-JWT VCs and mdocs, and what a verifier's `x509_hash` client id is computed from. Without a CA, certificates are
  self-signed, for development only.
- **Rotation** retires the active key, which stays published so what it signed still verifies, and creates a new one. A retired key can
  then be removed.

## Admin API (for the AuthStack console)

| Call | What it does |
|---|---|
| `GET /admin/api/tenants` | The tenants you may see. |
| `GET /admin/api/tenants/{environmentId}` | One tenant: its settings (secrets hidden), its URLs, its keys and certificates, and the CA. |
| `PUT /admin/api/tenants/{environmentId}` | Creates or changes the tenant: `{slug?, enabled?, settings?}`. A new tenant's slug defaults to its environment's name. |
| `POST /admin/api/tenants/{environmentId}/keys/{purpose}/rotate` | Rotates a key. |
| `DELETE /admin/api/tenants/{environmentId}/keys/{kid}` | Removes a retired key. |

**Who may do what.** Each call carries the signed-in person's AuthStack console token (`Authorization: Bearer`). The service asks
AuthStack (`GET /api/auth/me`) whose it is.
- **Platform `ADMIN`:** any tenant.
- **`ORG_ADMIN`:** the environments their organization owns.
- **`ORG_VIEWER`:** may only read.
- **Anyone else:** 404, so tenant ids can't be probed.

**Secrets.** Values under `settings.secrets` are write-only. They are shown as `{"set": true}`; sending that back keeps the value, and
`null` removes it.

**Your application's security configuration must** let `/admin/api/**` through without a session or CSRF token (the controller checks
the token itself), and enable CORS for the console's origin (`oid4vc.tenancy.admin.allowed-origins`).

## Tenant APIs (for the tenant's own backend)

The admin API is a person in the AuthStack console. A **tenant API** is the tenant's own backend calling a service as the tenant, machine
to machine: for example, the bank creating credential offers on the issuer. `TenantCallers` decides who may call one.

**`AuthStackTenantCallers`** accepts a client-credentials access token from an application of the **tenant's own** AuthStack environment
`E` only when:
- **its signature** verifies (RS256) with a key of `E`, from `<api>/E/as/jwks`. A token of any other environment fails the signature
  itself, not only a claim comparison. Keys are cached, and fetched again when a token names one not seen yet (rotation);
- **its claims** are right: `iss` is `<api>/E/as`, it hasn't expired, `type` is `client_credentials` and `environmentId` is `E`;
- **its application** (`client_id`) is listed in the tenant's settings. Any application of the environment could otherwise call, so an
  empty or missing list allows nobody:

```json
{ "tenantApi": { "clients": ["<application id>"] } }
```

Refusals are `401 invalid_token`, or `403 insufficient_scope` for an unlisted application. Use a **dedicated** worker application with no
roles for this; a worker that manages users shouldn't carry these calls. Without `oid4vc.tenancy.authstack.api-url`, every call is refused.

## A multi-tenant verifier

**What a request is for.** The verifier's endpoints name a relying party by its id, as in `/login/oid4vp/direct-post/{registrationId}`.
With tenancy, a request's tenant and that id together make the **registration key**, `<tenant>/<registrationId>`
(`Oid4vpRegistrationKey`). The default tenant's key is just the id.

**Everything is looked up by that key:**
- the registration;
- the stored request, so a `state` issued for one tenant's `login` is refused at another tenant's `login`;
- the request-object signing key and the response decryption keys;
- the ephemeral keys and the same-device result.

A single-tenant verifier sees exactly the ids it always has. Wire the configurer through `Oid4vpTenancy`:

```java
.with(Oid4vpLoginConfigurer.oid4vpLogin(), c -> c
        .tenantResolver(tenancy.tenantResolver())
        .relyingPartyRegistrationRepository(tenancy.registrations(registrations))
        .requestObjectSigningKeyResolver(tenancy.requestObjectSigningKeys(signingKeys))
        .issuerTrust(tenancy.issuerTrust(issuerKeyResolver))
        .dcApiOriginPolicy(tenancy.dcApiOriginPolicy())
        .walletInvocation(tenancy.url("/oid4vp/request", requestUriBase))
        .sameDeviceHandoff(results, tenancy.url("/oid4vp/result", resultBaseUri))
        ...)
```

**The default tenant** (`oid4vc.tenancy.default-tenant.id`) is the verifier as it was: the application's registrations, signing key,
issuer trust and URLs.

**Every other tenant** has:
- **its own registrations,** from its settings, with `response_uri`, `request_uri` and the result URL on the URL it was reached on;
- **its own `request-object` key,** certified by the deployment's CA. The key's certificate gives it its own `x509_hash` client id;
- **its own trust list:** a presentation from an issuer it doesn't list is refused;
- **its own DC API origins:** a Digital Credentials API response is accepted only when relayed by the tenant's own origin, or one it
  lists.

**Its settings:**

```json
{
  "registrations": {
    "login": { "dcqlQuery": { "credentials": [ ... ] }, "responseMode": "direct_post",
               "walletAuthorizationEndpoint": "openid4vp://authorize", "requestUriMethod": "get", "clientMetadata": { ... } }
  },
  "trustedIssuers": [
    { "issuer": "https://issuer.zkp.au/t/bank", "jwksUri": "https://issuer.zkp.au/t/bank/jwks" },
    { "issuer": "https://issuer.zkp.au", "x5cTrustAnchors": ["-----BEGIN CERTIFICATE-----..."] }
  ],
  "dcApiAllowedOrigins": ["https://app.bank.example"]
}
```

- **A trusted issuer** gives its keys inline (`jwks`), as a JWKS URL (`jwksUri`, https, fetched at most every five minutes), or as CA
  certificates (`x5cTrustAnchors`) that must have issued the credential's `x5c` leaf, which must be valid now.
- **Invalid settings** are refused by the console's admin API.
- **Without `Oid4vpTenancy`,** a verifier can still be multi-tenant by supplying its own `Oid4vpTenantResolver`, registration
  repository and `Oid4vpIssuerTrust`, keyed by registration key.

**The demo verifier** turns this on with profiles. Its default profile is unchanged and single-tenant.
- **`tenancy`:** the default tenant `irving` is the verifier as it was, on `https://verify.irving.au`, with its own relying parties, key
  and `x509_hash` client id. Other tenants are served from their settings. See `application-tenancy.yml` for the environment variables.
- **`postgres`:** keeps tenants, keys and the verifier's state in PostgreSQL. See `application-postgres.yml` for `VERIFIER_DATABASE_*`,
  `TENANT_KEY_ENCRYPTION_KEY` and `VERIFIER_STORE_ENCRYPTION_KEY`.
- **The demo page** stays on its path tenant (`/t/<slug>/`).

**Persistent state (`oid4vp-verifier-jdbc`).** Set `oid4vp.verifier.store.type=jdbc` to keep pending requests, ephemeral
response-encryption keys and same-device results in PostgreSQL, through the application's `DataSource`. Several instances share them,
and they survive a restart.
- **One table,** `oid4vp_verifier_entry`, created at start-up.
- **Keys** (`state`, transaction ids) and **owners** (the registration key, the response code) are stored only as SHA-256 hashes.
- **Payloads are encrypted with AES-256-GCM** under `oid4vp.verifier.store.encryption-key` (`VERIFIER_STORE_ENCRYPTION_KEY`, base64 of
  32 random bytes; required).
- **A request or result is consumed in one statement, and only by its owner:** a `state` presented at another registration, or a result
  collected with the wrong code, is left for its rightful use.

### Presentations for a tenant's backend

A tenant's backend can ask for a presentation and collect what was verified, without the verifier signing any browser in. Called as
the tenant (see [Tenant APIs](#tenant-apis-for-the-tenants-own-backend)), on the tenant's own URL:

```
POST /tenant-api/v1/transactions
{ "registrationId": "staff-sign-in",
  "expiresIn": 600,                                   // 60 to 600 seconds; 600 unless given
  "requestParameters": { "not_before_check": "…" },   // only names the registration lists; strings of at most 256 characters
  "reference": "<the backend's own name for it>" }
→ 201 { "transactionId", "requestUri", "walletUri": "openid4vp://?client_id=…&request_uri=…", "expiresAt", "reference" }

GET  /tenant-api/v1/transactions/{id}          → { "status": "pending" | "verified" | "collected" | "expired", … }
POST /tenant-api/v1/transactions/{id}/consume  → 200 { "credentials": { "<query id>": { "format", "issuer", "claims", "holderKey" } }, … }
                                                 once; 409 when there is nothing to collect
```

- **The request.** The wallet fetches a signed request object from `requestUri`, each time with a fresh `state` and `nonce`. It carries
  the transaction's parameters and `expires_at`. A registration lists what the backend may add:
  `"requestParameters": ["not_before_check"]`. The protocol's own parameters can't be listed.
- **Only a presentation that verifies answers it**, and only the first. A response that fails, or a wallet reporting an error, leaves
  it `pending` until it expires, so someone who is merely shown the request can't end it. There is no "rejected" status.
- **The result** waits ten minutes (`oid4vp.verifier.tenancy.transaction-result-ttl`) and is handed out once. With the `jdbc` store it
  is encrypted, and dropped when collected.
- **What a result means is the tenant's to decide.** It says the presentation is cryptographically valid, from an issuer the tenant
  trusts, and of a type the query asks for. When a tenant trusts several issuers, the backend checks which `issuer` issued which
  `vct`. An mdoc's claims name no issuer.
- **Whose browser.** Whoever shows the request to a wallet can answer it, so the backend binds the transaction to its own user's
  session, as it would for any cross-device presentation.
- **Limits.** The registration must use `direct_post` or `direct_post.jwt`, and no credential query may allow several presentations.

An application turns this on with `Oid4vpLoginConfigurer.transactions(oid4vpTransactions)` and lets `/tenant-api/**` through its
security: the API checks the caller's token itself.

## Configuration

```yaml
oid4vc:
  tenancy:
    enabled: true
    service: verifier                     # or issuer: which settings, and the AuthStack domain purpose
    platform-origins: [https://verifier.zkp.au]
    default-tenant: { id: irving, slug: irving }   # today's deployment, served on the platform origin itself
    store: { type: jdbc }                 # the application's DataSource (PostgreSQL); "memory" for tests
    keys:
      encryption-key: ${TENANT_KEY_ENCRYPTION_KEY}
      ca-keystore: file:/run/secrets/tenancy-ca.p12
      ca-keystore-password: ${TENANCY_CA_PASSWORD}
    authstack:
      api-url: https://<AuthStack API origin>
      token-url: https://<AuthStack API origin>/<administrator environment id>/as/token
      client-id: ${TENANCY_PLATFORM_CLIENT_ID}
      client-secret: ${TENANCY_PLATFORM_CLIENT_SECRET}
    admin:
      allowed-origins: [https://<the AuthStack console origin>]
```

The tables are created at start-up (`oid4vc-tenancy/schema-postgresql.sql`; turn this off with `store.initialize-schema=false`).

Tests: `mvn -pl oid4vc-tenancy test`. The PostgreSQL store tests run when `OID4VC_TEST_POSTGRES_URL` is set, for example
`jdbc:postgresql://localhost:55432/tenancy?user=tenancy&password=tenancy`.
