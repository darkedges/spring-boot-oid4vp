package com.darkedges.oid4vp.spring.boot.autoconfigure.tenancy;

import com.darkedges.oid4vc.tenancy.TenantContext;
import com.darkedges.oid4vc.tenancy.tenantapi.TenantCallers;
import com.darkedges.oid4vp.core.request.RequestUriMethod;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.transaction.Oid4vpTransaction;
import com.darkedges.oid4vp.spring.security.transaction.Oid4vpTransactions;
import com.darkedges.oid4vp.spring.security.web.Oid4vpTransactionRequestFilter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The tenant API for presentations: the tenant's own backend asks for one, and collects what was verified.
 * <pre>
 * POST /tenant-api/v1/transactions                     { registrationId, expiresIn?, requestParameters?, reference? }
 * GET  /tenant-api/v1/transactions/{id}                { status: pending | verified | collected | expired }
 * POST /tenant-api/v1/transactions/{id}/consume        { credentials: { "&lt;query id&gt;": { format, issuer?, claims, holderKey? } } }, once
 * </pre>
 * Called as the tenant, with a token from an application of the tenant's AuthStack environment that the tenant lists
 * ({@link TenantCallers}).
 *
 * <p>A result says the presentation is cryptographically valid, from an issuer the tenant trusts, and of a type the registration's
 * query asks for. What that means is the tenant's to decide: in particular, when a tenant trusts several issuers, which of them may
 * issue which type ({@code issuer} together with the claims' {@code vct}).
 */
@RestController
@RequestMapping(path = "/tenant-api/v1/transactions", produces = MediaType.APPLICATION_JSON_VALUE)
public class TenantTransactionController {

    private static final Logger audit = LoggerFactory.getLogger("oid4vp.tenant-api.audit");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    static final Pattern REFERENCE = Pattern.compile("[A-Za-z0-9._:-]{1,128}");
    static final int MAX_PARAMETER_LENGTH = 256;
    static final Duration DEFAULT_LIFETIME = Duration.ofMinutes(10), MIN_LIFETIME = Duration.ofMinutes(1), MAX_LIFETIME = Duration.ofMinutes(10);

    private final TenantCallers callers;
    private final Oid4vpTransactions transactions;
    private final Oid4vpTenancy tenancy;

    public TenantTransactionController(TenantCallers callers, Oid4vpTransactions transactions, Oid4vpTenancy tenancy) {
        this.callers = callers;
        this.transactions = transactions;
        this.tenancy = tenancy;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> create(@RequestHeader(name = "Authorization", required = false) String authorization,
                                         @RequestBody String rawBody, HttpServletRequest request) {
        Optional<ResponseEntity<String>> refused = refuseCaller(authorization, request);
        if (refused.isPresent()) return refused.get();
        TenantContext context = TenantContext.require(request);

        JsonNode body;
        try {
            body = MAPPER.readTree(rawBody);
        } catch (Exception e) {
            return error(400, "invalid_request", "The body is not JSON");
        }
        if (body == null || !body.isObject()) return error(400, "invalid_request", "The body must be a JSON object");

        String registrationId = body.path("registrationId").asText("");
        String registrationKey;
        try {
            registrationKey = tenancy.registrationKey(context.tenantId(), registrationId);
        } catch (IllegalArgumentException e) {
            return error(400, "invalid_request", "registrationId names one of the tenant's registrations");
        }
        Optional<Oid4vpRelyingPartyRegistration> registration = transactions.registration(registrationKey);
        if (registration.isEmpty()) return error(400, "invalid_request", "This verifier has no registration \"" + registrationId + "\"");

        Optional<String> reference = Optional.empty();
        if (body.hasNonNull("reference")) {
            String value = body.get("reference").asText();
            if (!REFERENCE.matcher(value).matches()) return error(400, "invalid_request", "reference is 1 to 128 of A-Z a-z 0-9 . _ : -");
            reference = Optional.of(value);
        }

        Map<String, String> parameters = new LinkedHashMap<>();
        JsonNode parametersNode = body.path("requestParameters");
        if (!parametersNode.isMissingNode() && !parametersNode.isObject()) {
            return error(400, "invalid_request", "requestParameters is an object of strings");
        }
        Set<String> allowed = tenancy.requestParameters(context.tenant(), registrationId);
        for (Map.Entry<String, JsonNode> parameter : parametersNode.properties()) {
            if (!allowed.contains(parameter.getKey())) {
                return error(400, "invalid_request", "The registration does not accept the request parameter \"" + parameter.getKey() + "\"");
            }
            if (!parameter.getValue().isTextual() || parameter.getValue().asText().length() > MAX_PARAMETER_LENGTH) {
                return error(400, "invalid_request", "Request parameter \"" + parameter.getKey() + "\" is a string of at most "
                        + MAX_PARAMETER_LENGTH + " characters");
            }
            parameters.put(parameter.getKey(), parameter.getValue().asText());
        }

        Duration lifetime = DEFAULT_LIFETIME;
        if (body.has("expiresIn")) {
            if (!body.get("expiresIn").canConvertToLong()) return error(400, "invalid_request", "expiresIn is a number of seconds");
            lifetime = Duration.ofSeconds(body.get("expiresIn").asLong());
            if (lifetime.compareTo(MIN_LIFETIME) < 0 || lifetime.compareTo(MAX_LIFETIME) > 0) {
                return error(400, "invalid_request", "expiresIn is between 60 and 600 seconds");
            }
        }

        Oid4vpTransaction transaction;
        try {
            transaction = transactions.create(registrationKey, reference, parameters, lifetime);
        } catch (IllegalArgumentException e) {
            return error(400, "invalid_request", e.getMessage());
        }
        String requestUri = context.url(Oid4vpTransactionRequestFilter.DEFAULT_PATH + "/" + transaction.requestId());
        audit.info("tenant {} asked for a presentation as {} (reference {})", context.tenantId(), registrationId, reference.orElse("-"));

        ObjectNode answer = describe(transaction).put("requestUri", requestUri)
                .put("walletUri", walletUri(registration.get(), requestUri));
        return json(201, answer);
    }

    @GetMapping("/{transactionId}")
    public ResponseEntity<String> status(@RequestHeader(name = "Authorization", required = false) String authorization,
                                         @PathVariable String transactionId, HttpServletRequest request) {
        Optional<ResponseEntity<String>> refused = refuseCaller(authorization, request);
        if (refused.isPresent()) return refused.get();
        Optional<Oid4vpTransaction> transaction = find(request, transactionId);
        if (transaction.isEmpty()) return error(404, "not_found", "No such transaction");
        return json(200, describe(transaction.get()).put("status", name(transactions.status(transaction.get()))));
    }

    @PostMapping("/{transactionId}/consume")
    public ResponseEntity<String> consume(@RequestHeader(name = "Authorization", required = false) String authorization,
                                          @PathVariable String transactionId, HttpServletRequest request) {
        Optional<ResponseEntity<String>> refused = refuseCaller(authorization, request);
        if (refused.isPresent()) return refused.get();
        Optional<Oid4vpTransaction> transaction = find(request, transactionId);
        if (transaction.isEmpty()) return error(404, "not_found", "No such transaction");
        Optional<Oid4vpPrincipal> result = transactions.collect(transaction.get());
        if (result.isEmpty()) {
            return error(409, "no_result", "There is no result to collect: the transaction is " + name(transactions.status(transaction.get())));
        }
        ObjectNode answer = describe(transaction.get());
        ObjectNode credentials = answer.putObject("credentials");
        result.get().presentations().forEach((queryId, list) -> {
            VerifiedPresentation presentation = list.getFirst(); // a transaction's queries take one presentation each
            ObjectNode credential = credentials.putObject(queryId).put("format", presentation.format().identifier());
            JsonNode issuer = presentation.verifiedClaims().path("iss"); // an mdoc names no issuer in its claims
            if (issuer.isTextual()) credential.put("issuer", issuer.asText());
            credential.set("claims", presentation.verifiedClaims());
            presentation.holderKeyConfirmed().ifPresent(key -> credential.set("holderKey", key));
        });
        audit.info("tenant {} collected the result of reference {}", TenantContext.require(request).tenantId(),
                transaction.get().reference().orElse("-"));
        return json(200, answer);
    }

    private Optional<Oid4vpTransaction> find(HttpServletRequest request, String transactionId) {
        // Only this tenant's: its transactions are under the same key as its registrations.
        return transactions.find(tenancy.tenantKey(TenantContext.require(request).tenantId()), transactionId);
    }

    private static ObjectNode describe(Oid4vpTransaction transaction) {
        ObjectNode node = MAPPER.createObjectNode().put("transactionId", transaction.transactionId())
                .put("expiresAt", transaction.expiresAt().toString());
        transaction.reference().ifPresent(reference -> node.put("reference", reference));
        return node;
    }

    private static String name(Oid4vpTransactions.Status status) {
        return status.name().toLowerCase(java.util.Locale.ROOT);
    }

    /** What opens the wallet: its authorization endpoint (the registration's, or {@code openid4vp://}) with the request by reference. */
    private static String walletUri(Oid4vpRelyingPartyRegistration registration, String requestUri) {
        // A string: "openid4vp://", with no authority, is not a java.net.URI.
        String endpoint = registration.walletAuthorizationEndpoint().map(URI::toString).orElse("openid4vp://");
        String uri = endpoint + (endpoint.contains("?") ? "&" : "?")
                + "client_id=" + URLEncoder.encode(registration.clientId().fullClientId(), StandardCharsets.UTF_8)
                + "&request_uri=" + URLEncoder.encode(requestUri, StandardCharsets.UTF_8);
        return registration.requestUriMethod() == RequestUriMethod.POST ? uri + "&request_uri_method=post" : uri;
    }

    /** Empty when the caller may act for the request's tenant; otherwise the answer to give. */
    private Optional<ResponseEntity<String>> refuseCaller(String authorization, HttpServletRequest request) {
        Optional<TenantContext> tenant = TenantContext.from(request);
        if (tenant.isEmpty()) return Optional.of(error(404, "not_found", "No tenant is served here"));
        String token = authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7) ? authorization.substring(7).trim() : null;
        try {
            callers.verify(token, tenant.get().tenant());
            return Optional.empty();
        } catch (TenantCallers.TenantCallerException e) {
            return Optional.of(error(e.status(), e.error(), e.getMessage()));
        }
    }

    private static ResponseEntity<String> json(int status, ObjectNode body) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).contentType(MediaType.APPLICATION_JSON).body(body.toString());
    }

    private static ResponseEntity<String> error(int status, String code, String description) {
        return json(status, MAPPER.createObjectNode().put("error", code).put("error_description", description));
    }
}
