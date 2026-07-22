package com.darkedges.oid4vp.spring.security.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Optional;

/** An authenticated token: the Wallet presented a {@code vp_token} that satisfied the DCQL query and
 * verified successfully. */
public class Oid4vpAuthenticationToken extends AbstractAuthenticationToken {

    private final Oid4vpPrincipal principal;
    private final String transactionId;

    public Oid4vpAuthenticationToken(Oid4vpPrincipal principal, Collection<? extends GrantedAuthority> authorities) {
        this(principal, authorities, null);
    }

    public Oid4vpAuthenticationToken(
            Oid4vpPrincipal principal, Collection<? extends GrantedAuthority> authorities, String transactionId) {
        super(authorities);
        this.principal = principal;
        this.transactionId = transactionId;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Oid4vpPrincipal getPrincipal() {
        return principal;
    }

    /** Present iff the originating Authorization Request was created with a {@code transactionId} (the
     * same-device {@code response_code}/{@code redirect_uri} handoff is in use for this response). */
    public Optional<String> transactionId() {
        return Optional.ofNullable(transactionId);
    }
}
