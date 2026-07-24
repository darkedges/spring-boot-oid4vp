package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.response.Oid4vpErrorCode;
import com.darkedges.oid4vp.core.response.ResponseDecryptionKeyResolver;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationException;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthorizationResponseAuthenticationToken;
import com.darkedges.oid4vp.verifier.encryption.ResponseDecryptor;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Optional;

/**
 * Reads a {@code direct_post}/{@code direct_post.jwt} form-encoded Authorization Response off the
 * request and resolves the matching {@link Oid4vpAuthorizationRequestContext}.
 *
 * <p>For {@code direct_post.jwt}, the request instead carries a single {@code response} field (an
 * encrypted JWE — see OpenID4VP 1.1 "Encrypted Responses"). Since its payload contains {@code state}
 * itself (there is nothing else to correlate by yet), the response decryption key is looked up by the
 * {@code registrationId} path variable instead — the same path segment the endpoint is already routed by.
 */
public class Oid4vpAuthorizationResponseAuthenticationConverter implements AuthenticationConverter {

    private final Oid4vpAuthorizationRequestRepository requestRepository;
    private final RequestMatcher requestMatcher;
    private final ResponseDecryptionKeyResolver decryptionKeyResolver;

    public Oid4vpAuthorizationResponseAuthenticationConverter(
            Oid4vpAuthorizationRequestRepository requestRepository,
            RequestMatcher requestMatcher,
            ResponseDecryptionKeyResolver decryptionKeyResolver) {
        this.requestRepository = requestRepository;
        this.requestMatcher = requestMatcher;
        this.decryptionKeyResolver = decryptionKeyResolver;
    }

    public Oid4vpAuthorizationResponseAuthenticationConverter(Oid4vpAuthorizationRequestRepository requestRepository) {
        this(requestRepository, null, null);
    }

    @Override
    public Oid4vpAuthorizationResponseAuthenticationToken convert(HttpServletRequest request) {
        String state;
        String error;
        String errorDescription;
        String vpTokenJson;
        String mdocGeneratedNonce = null;

        String responseJwe = request.getParameter("response");
        if (responseJwe != null) {
            JsonNode decrypted = decryptResponse(request, responseJwe);
            state = decrypted.path("state").asText(null);
            error = decrypted.hasNonNull("error") ? decrypted.get("error").asText() : null;
            errorDescription = decrypted.hasNonNull("error_description") ? decrypted.get("error_description").asText() : null;
            vpTokenJson = decrypted.has("vp_token") ? decrypted.get("vp_token").toString() : null;
            mdocGeneratedNonce = ResponseDecryptor.extractMdocGeneratedNonce(responseJwe).orElse(null);
        } else {
            state = request.getParameter("state");
            error = request.getParameter("error");
            errorDescription = request.getParameter("error_description");
            vpTokenJson = request.getParameter("vp_token");
        }

        if (state == null || state.isBlank()) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "missing required \"state\" parameter");
        }

        Oid4vpAuthorizationRequestContext context = requestRepository.consume(state)
                .orElseThrow(() -> new Oid4vpAuthenticationException(
                        Oid4vpErrorCode.INVALID_REQUEST, "unknown or expired \"state\": " + state));

        if (error != null) {
            return Oid4vpAuthorizationResponseAuthenticationToken.ofError(context, error, errorDescription);
        }

        if (vpTokenJson == null) {
            throw new Oid4vpAuthenticationException(Oid4vpErrorCode.INVALID_REQUEST, "missing required \"vp_token\" parameter");
        }

        return new Oid4vpAuthorizationResponseAuthenticationToken(context, vpTokenJson, null, mdocGeneratedNonce);
    }

    private JsonNode decryptResponse(HttpServletRequest request, String responseJwe) {
        if (decryptionKeyResolver == null || requestMatcher == null) {
            throw new Oid4vpAuthenticationException(
                    Oid4vpErrorCode.INVALID_REQUEST, "encrypted responses (direct_post.jwt) are not configured");
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
}
