package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

/**
 * Implements the {@code response_code}/{@code redirect_uri} same-device handoff from OpenID4VP 1.1,
 * "Response Mode direct_post" reference design: when the validated response's Authorization Request was
 * created with a {@code transactionId} (see {@link Oid4vpAuthorizationRequestService}), stores the
 * resulting {@link Authentication} under a fresh {@code response_code} and tells the Wallet to redirect
 * the End-User's browser to {@code <resultBaseUri>/<transactionId>?response_code=<code>}.
 *
 * <p>That URI is expected to be served by {@link Oid4vpTransactionResultFilter}, which completes the
 * handoff by looking the result up and establishing the {@code SecurityContext} for that browser request
 * — collapsing the reference design's separate "redirect" and "fetch response data" steps into one.
 *
 * <p>Falls back to a plain {@code {}} acknowledgement (no redirect) when the request didn't use a
 * {@code transactionId} — e.g. cross-device flows, or same-device flows not using this handoff.
 */
public class Oid4vpSameDeviceAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final int RESPONSE_CODE_BYTES = 16; // 128 bits

    private final Oid4vpTransactionResultRepository transactionResultRepository;
    private final String resultBaseUri;
    private final SecureRandom random = new SecureRandom();

    /** @param resultBaseUri e.g. {@code "https://verifier.example.org/oid4vp/result"} — the
     *                       transactionId and {@code ?response_code=} are appended to this. */
    public Oid4vpSameDeviceAuthenticationSuccessHandler(
            Oid4vpTransactionResultRepository transactionResultRepository, String resultBaseUri) {
        this.transactionResultRepository = transactionResultRepository;
        this.resultBaseUri = resultBaseUri;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
        Optional<String> transactionId = authentication instanceof Oid4vpAuthenticationToken token
                ? token.transactionId()
                : Optional.empty();

        if (transactionId.isEmpty()) {
            writeJson(response, "{}");
            return;
        }

        String responseCode = randomUrlSafeToken();
        transactionResultRepository.save(transactionId.get(), responseCode, authentication);

        String redirectUri = resultBaseUri + "/" + transactionId.get() + "?response_code=" + responseCode;
        writeJson(response, "{\"redirect_uri\":\"" + redirectUri + "\"}");
    }

    private String randomUrlSafeToken() {
        byte[] bytes = new byte[RESPONSE_CODE_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void writeJson(HttpServletResponse response, String body) throws IOException {
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.getWriter().write(body);
    }
}
