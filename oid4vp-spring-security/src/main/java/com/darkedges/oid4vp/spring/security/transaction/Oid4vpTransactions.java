package com.darkedges.oid4vp.spring.security.transaction;

import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.response.Oid4vpErrorCode;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationException;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthenticationToken;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthorizationResponseAuthenticationToken;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpPrincipal;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestResolution;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * Presentations asked for by an application's backend. It {@linkplain #create creates} a transaction, shows the wallet the request,
 * polls {@linkplain #status its status} and {@linkplain #collect collects} the verified result once.
 *
 * <p>Only a presentation that verifies answers a transaction. A response that fails (a wrong signature, an untrusted issuer, a wallet
 * reporting an error) leaves it pending until it expires: anyone shown the request could send one, and must not be able to end it.
 * The wallet may fetch the request again and answer properly.
 */
public final class Oid4vpTransactions {

    public enum Status { PENDING, VERIFIED, COLLECTED, EXPIRED }

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Oid4vpTransactionStore store;
    private final Oid4vpAuthorizationRequestService requests;
    private final Clock clock;
    private final Duration resultTtl;

    public Oid4vpTransactions(Oid4vpTransactionStore store, Oid4vpAuthorizationRequestService requests, Clock clock, Duration resultTtl) {
        this.store = store;
        this.requests = requests;
        this.clock = clock;
        this.resultTtl = resultTtl;
    }

    /** The relying party a transaction under this key would ask as. */
    public Optional<Oid4vpRelyingPartyRegistration> registration(String registrationKey) {
        return requests.registration(registrationKey);
    }

    /**
     * @throws IllegalArgumentException for an unknown relying party, or one a transaction can't be made for: its response must be posted
     *                                  here ({@code direct_post}), and each credential query answered by one presentation
     */
    public Oid4vpTransaction create(String registrationKey, Optional<String> reference, Map<String, String> requestParameters,
                                    Duration lifetime) {
        Oid4vpRelyingPartyRegistration registration = registration(registrationKey)
                .orElseThrow(() -> new IllegalArgumentException("unknown relying party registration"));
        ResponseMode mode = registration.responseMode();
        if ((mode != ResponseMode.DIRECT_POST && mode != ResponseMode.DIRECT_POST_JWT) || registration.codeFlow().isPresent()) {
            throw new IllegalArgumentException("a transaction needs a relying party that uses direct_post or direct_post.jwt");
        }
        if (registration.dcqlQuery().get().credentials().stream().anyMatch(CredentialQuery::multiple)) {
            throw new IllegalArgumentException("a transaction can't use a credential query that allows several presentations");
        }
        Oid4vpTransaction transaction = new Oid4vpTransaction(randomToken(), randomToken(), registrationKey, reference,
                requestParameters, clock.instant().plus(lifetime));
        store.save(transaction);
        return transaction;
    }

    public Optional<Oid4vpTransaction> find(String tenantId, String transactionId) {
        return store.find(tenantId, transactionId);
    }

    public Status status(Oid4vpTransaction transaction) {
        Instant now = clock.instant();
        Optional<Oid4vpTransactionStore.Answer> answer = store.answerOf(transaction);
        if (answer.isPresent()) {
            if (answer.get().resultCollected()) return Status.COLLECTED;
            return answer.get().resultExpiresAt().isAfter(now) ? Status.VERIFIED : Status.EXPIRED;
        }
        return transaction.expiresAt().isAfter(now) ? Status.PENDING : Status.EXPIRED;
    }

    public Optional<Oid4vpPrincipal> collect(Oid4vpTransaction transaction) {
        return store.collect(transaction);
    }

    /** The transaction whose hosted request this is, while a wallet may still answer it. */
    public Optional<Oid4vpTransaction> awaiting(String tenantId, String requestId) {
        return store.findByRequestId(tenantId, requestId).filter(transaction -> status(transaction) == Status.PENDING);
    }

    /** A fresh Authorization Request for the transaction, with its own {@code state} and {@code nonce}. */
    public Oid4vpAuthorizationRequestResolution request(Oid4vpTransaction transaction) {
        return requests.resolve(transaction.registrationKey(), transaction.transactionId(), transaction.expiresAt());
    }

    /** Whether this verified presentation answered a transaction, so no browser is waiting to be signed in with it. */
    public boolean isAnswer(Authentication authentication) {
        return authentication instanceof Oid4vpAuthenticationToken token
                && token.transactionId().flatMap(id -> store.find(token.tenantId(), id)).isPresent();
    }

    /** {@code delegate}, with a verified presentation of a transaction's request recorded as its result. */
    public AuthenticationManager recording(AuthenticationManager delegate) {
        return authentication -> {
            Optional<Oid4vpTransaction> transaction = transactionOf(authentication);
            if (transaction.isEmpty()) return delegate.authenticate(authentication);
            if (status(transaction.get()) != Status.PENDING) throw closed();
            Authentication verified = delegate.authenticate(authentication);
            Oid4vpPrincipal principal = (Oid4vpPrincipal) verified.getPrincipal();
            if (!store.answer(transaction.get(), principal, clock.instant().plus(resultTtl))) throw closed();
            return verified;
        };
    }

    private Optional<Oid4vpTransaction> transactionOf(Authentication authentication) {
        if (!(authentication instanceof Oid4vpAuthorizationResponseAuthenticationToken token)) return Optional.empty();
        var context = token.requestContext();
        String tenantId = com.darkedges.oid4vp.spring.security.registration.Oid4vpRegistrationKey.tenantOf(context.registrationId());
        return context.transactionId().flatMap(id -> store.find(tenantId, id))
                .filter(transaction -> transaction.registrationKey().equals(context.registrationId()));
    }

    private static Oid4vpAuthenticationException closed() {
        return new Oid4vpAuthenticationException(Oid4vpErrorCode.ACCESS_DENIED, "this request has already been answered or has expired");
    }

    private static String randomToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
