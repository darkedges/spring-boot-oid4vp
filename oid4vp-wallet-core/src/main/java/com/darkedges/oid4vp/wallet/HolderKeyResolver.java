package com.darkedges.oid4vp.wallet;

import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.nimbusds.jose.JWSSigner;

import java.util.Optional;

/**
 * Resolves the {@link JWSSigner} for the private key backing a held credential's Cryptographic Holder
 * Binding confirmation key ({@code cnf}), so a {@link PresentationBuilder} can sign a Key Binding JWT.
 *
 * <p>Unlike {@code IssuerKeyResolver}/{@code ResponseDecryptionKeyResolver} elsewhere in this project,
 * this is not crypto-agnostic (it returns a Nimbus type directly): the Wallet always already possesses
 * its own private key material in some concrete form, so there's no raw-JSON exchange format to abstract
 * over — implementations just need to look it up (a local keystore, a hardware-backed key, a KMS, ...)
 * and hand back something that can sign.
 */
public interface HolderKeyResolver {

    Optional<JWSSigner> resolveSigner(HeldCredential credential);
}
