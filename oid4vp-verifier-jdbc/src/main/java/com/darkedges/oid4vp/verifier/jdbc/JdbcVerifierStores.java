package com.darkedges.oid4vp.verifier.jdbc;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.DcqlQueryReader;
import com.darkedges.oid4vp.core.dcql.DcqlQueryWriter;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefixParser;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationToken;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestContext;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpEphemeralEncryptionKeyRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpTransactionResultRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import java.io.IOException;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The verifier's stores in PostgreSQL, all in {@link VerifierEntryTable}. Registration ids here are
 * {@linkplain com.darkedges.oid4vp.spring.security.registration.Oid4vpRegistrationKey registration keys}, so a tenant's entries are
 * its own.
 */
public final class JdbcVerifierStores {

    public static final String REQUEST_CONTEXT = "request_context";
    public static final String EPHEMERAL_KEY = "ephemeral_key";
    public static final String TRANSACTION_RESULT = "transaction_result";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JdbcVerifierStores() {}

    /** Pending Authorization Requests by {@code state}, each owned by its registration and used once. */
    public static final class AuthorizationRequests implements Oid4vpAuthorizationRequestRepository {
        private final VerifierEntryTable table;
        private final Clock clock;

        public AuthorizationRequests(VerifierEntryTable table, Clock clock) {
            this.table = table;
            this.clock = clock;
        }

        @Override
        public void save(Oid4vpAuthorizationRequestContext context) {
            table.put(REQUEST_CONTEXT, context.state(), context.registrationId(), bytes(write(context)), context.expiresAt());
        }

        @Override
        public Optional<Oid4vpAuthorizationRequestContext> consume(String state) {
            return live(table.takeAny(REQUEST_CONTEXT, state));
        }

        /** Atomic: a {@code state} presented at another registration's endpoint is left for the genuine response. */
        @Override
        public Optional<Oid4vpAuthorizationRequestContext> consume(String state, String registrationId) {
            return live(table.take(REQUEST_CONTEXT, state, registrationId));
        }

        private Optional<Oid4vpAuthorizationRequestContext> live(Optional<VerifierEntryTable.Entry> entry) {
            return entry.map(e -> read(json(e.payload()))).filter(context -> !context.isExpired(clock.instant()));
        }

        static ObjectNode write(Oid4vpAuthorizationRequestContext c) {
            ObjectNode node = MAPPER.createObjectNode()
                    .put("registrationId", c.registrationId()).put("state", c.state()).put("nonce", c.nonce())
                    .put("clientId", c.clientId().fullClientId()).put("responseUri", c.responseUri().toString())
                    .put("expiresAt", c.expiresAt().toString());
            node.set("dcqlQuery", DcqlQueryWriter.write(c.dcqlQuery()));
            c.transactionId().ifPresent(t -> node.put("transactionId", t));
            c.codeVerifier().ifPresent(v -> node.put("codeVerifier", v));
            return node;
        }

        static Oid4vpAuthorizationRequestContext read(JsonNode n) {
            return new Oid4vpAuthorizationRequestContext(n.path("registrationId").asText(), n.path("state").asText(),
                    n.path("nonce").asText(), ClientIdentifierPrefixParser.parse(n.path("clientId").asText()),
                    DcqlQueryReader.read(n.path("dcqlQuery")), URI.create(n.path("responseUri").asText()),
                    Instant.parse(n.path("expiresAt").asText()), text(n, "transactionId"), text(n, "codeVerifier"));
        }
    }

    /** Ephemeral response-encryption keys, owned by their registration. */
    public static final class EphemeralEncryptionKeys implements Oid4vpEphemeralEncryptionKeyRepository {
        private final VerifierEntryTable table;

        public EphemeralEncryptionKeys(VerifierEntryTable table) {
            this.table = table;
        }

        @Override
        public void save(String registrationId, JsonNode privateJwk, Instant expiresAt) {
            String kid = privateJwk.path("kid").asText(null);
            if (kid == null || kid.isBlank()) throw new IllegalArgumentException("privateJwk must have a \"kid\"");
            table.put(EPHEMERAL_KEY, registrationId + "|" + kid, registrationId, bytes(privateJwk), expiresAt);
        }

        @Override
        public JsonNode resolveLiveKeys(String registrationId, Instant now) {
            ObjectNode jwks = MAPPER.createObjectNode();
            ArrayNode keys = jwks.putArray("keys");
            table.ofOwner(EPHEMERAL_KEY, registrationId, now).forEach(payload -> keys.add(json(payload)));
            return jwks;
        }
    }

    /**
     * Same-device results: a verified presentation, collected once with its response code. A wrong code leaves the result for the
     * browser that holds the right one.
     */
    public static final class TransactionResults implements Oid4vpTransactionResultRepository {
        private final VerifierEntryTable table;
        private final Clock clock;
        private final Duration ttl;

        public TransactionResults(VerifierEntryTable table, Clock clock, Duration ttl) {
            this.table = table;
            this.clock = clock;
            this.ttl = ttl;
        }

        @Override
        public void save(String transactionId, String responseCode, Authentication authentication) {
            if (!(authentication instanceof Oid4vpAuthenticationToken token)) {
                throw new IllegalArgumentException("only an Oid4vpAuthenticationToken can be kept as a same-device result");
            }
            table.put(TRANSACTION_RESULT, transactionId, responseCode, bytes(write(token)), clock.instant().plus(ttl));
        }

        @Override
        public Optional<Authentication> consume(String transactionId, String responseCode) {
            if (transactionId == null || responseCode == null) return Optional.empty();
            return table.take(TRANSACTION_RESULT, transactionId, responseCode)
                    .filter(e -> e.expiresAt().isAfter(clock.instant()))
                    .map(e -> read(json(e.payload())));
        }

        static ObjectNode write(Oid4vpAuthenticationToken token) {
            ObjectNode node = MAPPER.createObjectNode().put("registrationKey", token.registrationKey());
            token.transactionId().ifPresent(t -> node.put("transactionId", t));
            ObjectNode presentations = node.putObject("presentations");
            token.getPrincipal().presentations().forEach((queryId, list) -> {
                ArrayNode array = presentations.putArray(queryId);
                for (VerifiedPresentation p : list) {
                    ObjectNode entry = array.addObject().put("credentialQueryId", p.credentialQueryId()).put("format", p.format().identifier());
                    entry.set("verifiedClaims", p.verifiedClaims());
                    p.holderKeyConfirmed().ifPresent(k -> entry.set("holderKeyConfirmed", k));
                }
            });
            return node;
        }

        static Oid4vpAuthenticationToken read(JsonNode n) {
            Map<String, List<VerifiedPresentation>> presentations = new LinkedHashMap<>();
            n.path("presentations").fields().forEachRemaining(e -> {
                List<VerifiedPresentation> list = new ArrayList<>();
                for (JsonNode p : e.getValue()) {
                    list.add(new VerifiedPresentation(p.path("credentialQueryId").asText(), CredentialFormat.fromIdentifier(p.path("format").asText()),
                            p.path("verifiedClaims"), p.hasNonNull("holderKeyConfirmed") ? Optional.of(p.get("holderKeyConfirmed")) : Optional.empty()));
                }
                presentations.put(e.getKey(), list);
            });
            Oid4vpAuthenticationToken token = new Oid4vpAuthenticationToken(new Oid4vpPrincipal(presentations),
                    AuthorityUtils.NO_AUTHORITIES, n.hasNonNull("transactionId") ? n.get("transactionId").asText() : null);
            token.setRegistrationKey(n.path("registrationKey").asText());
            return token;
        }
    }

    private static Optional<String> text(JsonNode node, String field) {
        return node.hasNonNull(field) ? Optional.of(node.get(field).asText()) : Optional.empty();
    }

    private static byte[] bytes(JsonNode node) {
        try {
            return MAPPER.writeValueAsBytes(node);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static JsonNode json(byte[] bytes) {
        try {
            return MAPPER.readTree(bytes);
        } catch (IOException e) {
            throw new IllegalStateException("unreadable verifier entry", e);
        }
    }
}
