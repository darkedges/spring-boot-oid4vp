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

import com.darkedges.oid4vp.spring.security.transaction.Oid4vpTransaction;
import com.darkedges.oid4vp.spring.security.transaction.Oid4vpTransactionStore;
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
    public static final String TRANSACTION = "transaction";
    public static final String TRANSACTION_REQUEST = "transaction_request";
    public static final String TRANSACTION_ANSWER = "transaction_answer";
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
            node.set("presentations", writePresentations(token.getPrincipal()));
            return node;
        }

        static Oid4vpAuthenticationToken read(JsonNode n) {
            Oid4vpAuthenticationToken token = new Oid4vpAuthenticationToken(principal(n.path("presentations")),
                    AuthorityUtils.NO_AUTHORITIES, n.hasNonNull("transactionId") ? n.get("transactionId").asText() : null);
            token.setRegistrationKey(n.path("registrationKey").asText());
            return token;
        }
    }

    /**
     * Backend transactions. The transaction and its request id are kept an hour past expiry, so its status can still be told. An answer
     * is added once (the first presentation wins) under the tenant; collecting it hands it to one caller and drops the claims.
     */
    public static final class Transactions implements Oid4vpTransactionStore {
        private static final Duration RETENTION = Duration.ofHours(1);
        private static final String COLLECTED = "|collected";
        private final VerifierEntryTable table;
        private final Clock clock;

        public Transactions(VerifierEntryTable table, Clock clock) {
            this.table = table;
            this.clock = clock;
        }

        @Override
        public void save(Oid4vpTransaction t) {
            ObjectNode node = MAPPER.createObjectNode().put("transactionId", t.transactionId()).put("requestId", t.requestId())
                    .put("registrationKey", t.registrationKey()).put("expiresAt", t.expiresAt().toString());
            t.reference().ifPresent(r -> node.put("reference", r));
            ObjectNode parameters = node.putObject("requestParameters");
            t.requestParameters().forEach(parameters::put);
            Instant keepUntil = t.expiresAt().plus(RETENTION);
            table.put(TRANSACTION, t.transactionId(), t.tenantId(), bytes(node), keepUntil);
            table.put(TRANSACTION_REQUEST, t.requestId(), t.tenantId(),
                    bytes(MAPPER.createObjectNode().put("transactionId", t.transactionId())), keepUntil);
        }

        @Override
        public Optional<Oid4vpTransaction> find(String tenantId, String transactionId) {
            if (transactionId == null) return Optional.empty();
            return table.find(TRANSACTION, transactionId, tenantId).map(entry -> {
                JsonNode n = json(entry.payload());
                Map<String, String> parameters = new LinkedHashMap<>();
                n.path("requestParameters").fields().forEachRemaining(f -> parameters.put(f.getKey(), f.getValue().asText()));
                return new Oid4vpTransaction(n.path("transactionId").asText(), n.path("requestId").asText(),
                        n.path("registrationKey").asText(), text(n, "reference"), parameters, Instant.parse(n.path("expiresAt").asText()));
            });
        }

        @Override
        public Optional<Oid4vpTransaction> findByRequestId(String tenantId, String requestId) {
            if (requestId == null) return Optional.empty();
            return table.find(TRANSACTION_REQUEST, requestId, tenantId)
                    .flatMap(entry -> find(tenantId, json(entry.payload()).path("transactionId").asText()));
        }

        @Override
        public boolean answer(Oid4vpTransaction t, Oid4vpPrincipal result, Instant resultExpiresAt) {
            ObjectNode node = MAPPER.createObjectNode().put("resultExpiresAt", resultExpiresAt.toString());
            node.set("presentations", writePresentations(result));
            Instant keepUntil = t.expiresAt().isAfter(resultExpiresAt) ? t.expiresAt() : resultExpiresAt;
            return table.putIfAbsent(TRANSACTION_ANSWER, t.transactionId(), t.tenantId(), bytes(node), keepUntil.plus(RETENTION));
        }

        @Override
        public Optional<Answer> answerOf(Oid4vpTransaction t) {
            Optional<VerifierEntryTable.Entry> waiting = table.find(TRANSACTION_ANSWER, t.transactionId(), t.tenantId());
            if (waiting.isPresent()) return waiting.map(e -> new Answer(false, resultExpiry(json(e.payload()))));
            return table.find(TRANSACTION_ANSWER, t.transactionId(), t.tenantId() + COLLECTED)
                    .map(e -> new Answer(true, resultExpiry(json(e.payload()))));
        }

        @Override
        public Optional<Oid4vpPrincipal> collect(Oid4vpTransaction t) {
            String waiting = t.tenantId();
            String collected = waiting + COLLECTED;
            Optional<JsonNode> answer = table.find(TRANSACTION_ANSWER, t.transactionId(), waiting).map(e -> json(e.payload()));
            if (answer.isEmpty() || !resultExpiry(answer.get()).isAfter(clock.instant())
                    || !table.changeOwner(TRANSACTION_ANSWER, t.transactionId(), waiting, collected)) {
                return Optional.empty();
            }
            // Handed out: only the fact of the answer is kept.
            Instant resultExpiresAt = resultExpiry(answer.get());
            table.put(TRANSACTION_ANSWER, t.transactionId(), collected,
                    bytes(MAPPER.createObjectNode().put("resultExpiresAt", resultExpiresAt.toString())),
                    (t.expiresAt().isAfter(resultExpiresAt) ? t.expiresAt() : resultExpiresAt).plus(RETENTION));
            return Optional.of(principal(answer.get().path("presentations")));
        }

        private static Instant resultExpiry(JsonNode answer) {
            return Instant.parse(answer.path("resultExpiresAt").asText());
        }
    }

    private static ObjectNode writePresentations(Oid4vpPrincipal principal) {
        ObjectNode presentations = MAPPER.createObjectNode();
        principal.presentations().forEach((queryId, list) -> {
            ArrayNode array = presentations.putArray(queryId);
            for (VerifiedPresentation p : list) {
                ObjectNode entry = array.addObject().put("credentialQueryId", p.credentialQueryId()).put("format", p.format().identifier());
                entry.set("verifiedClaims", p.verifiedClaims());
                p.holderKeyConfirmed().ifPresent(k -> entry.set("holderKeyConfirmed", k));
            }
        });
        return presentations;
    }

    private static Oid4vpPrincipal principal(JsonNode stored) {
        Map<String, List<VerifiedPresentation>> presentations = new LinkedHashMap<>();
        stored.fields().forEachRemaining(e -> {
            List<VerifiedPresentation> list = new ArrayList<>();
            for (JsonNode p : e.getValue()) {
                list.add(new VerifiedPresentation(p.path("credentialQueryId").asText(), CredentialFormat.fromIdentifier(p.path("format").asText()),
                        p.path("verifiedClaims"), p.hasNonNull("holderKeyConfirmed") ? Optional.of(p.get("holderKeyConfirmed")) : Optional.empty()));
            }
            presentations.put(e.getKey(), list);
        });
        return new Oid4vpPrincipal(presentations);
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
