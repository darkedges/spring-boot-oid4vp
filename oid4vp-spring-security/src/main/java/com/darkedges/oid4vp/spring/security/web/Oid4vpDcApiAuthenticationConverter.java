package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.response.Oid4vpErrorCode;
import com.darkedges.oid4vp.core.response.ResponseDecryptionKeyResolver;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationException;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthorizationResponseAuthenticationToken;
import com.darkedges.oid4vp.verifier.encryption.ResponseDecryptor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Optional;

/**
 * Reads an Authorization Response received via the Digital Credentials API.
 *
 * <p>OpenID4VP over the DC API is browser-mediated: the Wallet's response reaches the page as a
 * {@code DigitalCredential}'s {@code data} property, and it's up to the page's own JavaScript to relay
 * that to the Verifier's backend — this converter expects that relay to be a JSON POST body shaped
 * exactly like {@code DigitalCredential.data}: {@code {"vp_token": {...}, "state": "..."}},
 * {@code {"response": "<jwe>"}} (encrypted), or {@code {"error": "..."}}.
 *
 * <p>Since there is no {@code client_id}-based channel, the expected audience is
 * {@code origin:<origin>}, taken from the relay request's {@code Origin} header — which, for a same-page
 * same-origin relay (the expected architecture), is the same origin the Wallet bound the presentation to.
 */
public class Oid4vpDcApiAuthenticationConverter implements AuthenticationConverter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Oid4vpAuthorizationRequestRepository requestRepository;
    private final RequestMatcher requestMatcher;
    private final ResponseDecryptionKeyResolver decryptionKeyResolver;

    public Oid4vpDcApiAuthenticationConverter(
            Oid4vpAuthorizationRequestRepository requestRepository,
            RequestMatcher requestMatcher,
            ResponseDecryptionKeyResolver decryptionKeyResolver) {
        this.requestRepository = requestRepository;
        this.requestMatcher = requestMatcher;
        this.decryptionKeyResolver = decryptionKeyResolver;
    }

    @Override
    public Oid4vpAuthorizationResponseAuthenticationToken convert(HttpServletRequest request) {
        String origin = request.getHeader("Origin");
        if (origin == null || origin.isBlank()) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "missing required \"Origin\" header");
        }
        String audienceOverride = "origin:" + origin;

        JsonNode body = readJsonBody(request);

        String state;
        String error;
        String errorDescription;
        String vpTokenJson;
        String mdocGeneratedNonce = null;

        if (body.hasNonNull("response")) {
            String responseJwe = body.get("response").asText();
            JsonNode decrypted = decryptResponse(request, responseJwe);
            state = decrypted.path("state").asText(null);
            error = decrypted.hasNonNull("error") ? decrypted.get("error").asText() : null;
            errorDescription = decrypted.hasNonNull("error_description") ? decrypted.get("error_description").asText() : null;
            vpTokenJson = decrypted.has("vp_token") ? decrypted.get("vp_token").toString() : null;
            mdocGeneratedNonce = ResponseDecryptor.extractMdocGeneratedNonce(responseJwe).orElse(null);
        } else {
            state = body.path("state").asText(null);
            error = body.hasNonNull("error") ? body.get("error").asText() : null;
            errorDescription = body.hasNonNull("error_description") ? body.get("error_description").asText() : null;
            vpTokenJson = body.has("vp_token") ? body.get("vp_token").toString() : null;
        }

        if (state == null || state.isBlank()) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "missing required \"state\"");
        }

        Oid4vpAuthorizationRequestContext context = requestRepository.consume(state)
                .orElseThrow(() -> new Oid4vpAuthenticationException(
                        Oid4vpErrorCode.INVALID_REQUEST, "unknown or expired \"state\": " + state));

        if (error != null) {
            return Oid4vpAuthorizationResponseAuthenticationToken.ofError(context, error, errorDescription, audienceOverride);
        }

        if (vpTokenJson == null) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "missing required \"vp_token\"");
        }

        return new Oid4vpAuthorizationResponseAuthenticationToken(context, vpTokenJson, audienceOverride, mdocGeneratedNonce);
    }

    private JsonNode decryptResponse(HttpServletRequest request, String responseJwe) {
        if (decryptionKeyResolver == null) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "encrypted responses (dc_api.jwt) are not configured");
        }
        String registrationId = extractRegistrationId(request);
        JsonNode privateJwks = decryptionKeyResolver.resolvePrivateJwks(registrationId)
                .orElseThrow(() -> new Oid4vpAuthenticationException(
                        Oid4vpErrorCode.INVALID_REQUEST, "no response decryption key configured for registration: " + registrationId));
        return ResponseDecryptor.decrypt(responseJwe, privateJwks);
    }

    private String extractRegistrationId(HttpServletRequest request) {
        RequestMatcher.MatchResult result = requestMatcher.matcher(request);
        return Optional.ofNullable(result.getVariables().get("registrationId"))
                .orElseThrow(() -> new Oid4vpAuthenticationException(
                        Oid4vpErrorCode.INVALID_REQUEST, "could not resolve registrationId from request path"));
    }

    private static JsonNode readJsonBody(HttpServletRequest request) {
        try {
            return MAPPER.readTree(request.getInputStream());
        } catch (JsonProcessingException e) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "request body is not valid JSON", e);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read request body", e);
        }
    }
}
