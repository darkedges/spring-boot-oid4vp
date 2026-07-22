package com.darkedges.oid4vp.core.dcql.eval;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;

import java.util.List;

/** The set of Credentials a Wallet holds, as seen by the {@link DcqlEvaluator}. */
public interface CredentialStore {

    List<HeldCredential> findAll();

    default List<HeldCredential> findByFormat(CredentialFormat format) {
        return findAll().stream().filter(c -> c.format() == format).toList();
    }

    static CredentialStore of(List<HeldCredential> credentials) {
        List<HeldCredential> copy = List.copyOf(credentials);
        return () -> copy;
    }
}
