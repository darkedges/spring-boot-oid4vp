package com.darkedges.oid4vp.spring.security.transaction;

import com.darkedges.oid4vp.spring.security.registration.Oid4vpRegistrationKey;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * One presentation an application's backend asked for: it hands the wallet a request, then collects the verified result itself, rather
 * than having a browser signed in.
 *
 * @param transactionId     the backend's handle for it, never sent to a wallet
 * @param requestId         names the hosted request the wallet fetches; knowing it gives no access to the result
 * @param registrationKey   the relying party (and tenant) it asks as
 * @param reference         the backend's own name for it, if it gave one
 * @param requestParameters extra parameters copied into the request object
 * @param expiresAt         until when a wallet may answer
 */
public record Oid4vpTransaction(
        String transactionId,
        String requestId,
        String registrationKey,
        Optional<String> reference,
        Map<String, String> requestParameters,
        Instant expiresAt) {

    public Oid4vpTransaction {
        Objects.requireNonNull(transactionId, "transactionId");
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(registrationKey, "registrationKey");
        Objects.requireNonNull(expiresAt, "expiresAt");
        reference = reference == null ? Optional.empty() : reference;
        requestParameters = requestParameters == null ? Map.of() : Map.copyOf(requestParameters);
    }

    public String tenantId() {
        return Oid4vpRegistrationKey.tenantOf(registrationKey);
    }
}
