package com.darkedges.oid4vp.sdjwt;

import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;
import com.darkedges.oid4vp.core.dcql.ClaimsPathPointerException;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQueryMeta;
import com.darkedges.oid4vp.core.dcql.PathComponent;
import com.darkedges.oid4vp.core.dcql.SdJwtVcMeta;
import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A {@code dc+sd-jwt} Credential as held by a Wallet: an issuance-form SD-JWT (all Disclosures, no Key
 * Binding JWT) that has been signature- and digest-verified so its full claim set is available for DCQL
 * evaluation.
 */
public final class SdJwtVcHeldCredential implements HeldCredential {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final SdJwt issuanceForm;
    private final JsonNode rawIssuerPayload;
    private final JsonNode claimsView;
    private final String vct;

    private SdJwtVcHeldCredential(SdJwt issuanceForm, JsonNode rawIssuerPayload, JsonNode claimsView, String vct) {
        this.issuanceForm = issuanceForm;
        this.rawIssuerPayload = rawIssuerPayload;
        this.claimsView = claimsView;
        this.vct = vct;
    }

    /** Parses an issuance-form SD-JWT string and digest-verifies it (does <em>not</em> verify the
     * issuer's signature — that happens at presentation-verification time via {@link SdJwtVerifier}; a
     * Wallet's local credential store is trusted storage, not an adversarial input). */
    public static SdJwtVcHeldCredential parse(String issuanceFormSerialized) {
        SdJwt sdJwt = SdJwtParser.parse(issuanceFormSerialized);
        JsonNode payload = decodePayload(sdJwt);
        JsonNode claimsView = SdJwtDigestVerifier.verify(payload, sdJwt.disclosures());
        String vct = payload.path("vct").asText(null);
        if (vct == null) {
            throw new IllegalArgumentException("SD-JWT VC payload is missing required \"vct\" claim");
        }
        return new SdJwtVcHeldCredential(sdJwt, payload, claimsView, vct);
    }

    private static JsonNode decodePayload(SdJwt sdJwt) {
        try {
            return MAPPER.readTree(sdJwt.issuerSignedJwt().getPayload().toBytes());
        } catch (Exception e) {
            throw new IllegalArgumentException("SD-JWT issuer-signed JWT payload is not valid JSON", e);
        }
    }

    public SdJwt issuanceForm() {
        return issuanceForm;
    }

    public String vct() {
        return vct;
    }

    @Override
    public CredentialFormat format() {
        return CredentialFormat.DC_SD_JWT;
    }

    @Override
    public JsonNode claimsView() {
        return claimsView;
    }

    @Override
    public boolean isSelectivelyDisclosable(ClaimsPathPointer path) {
        // Present in the digest-verified view but not in the raw (still-hashed) payload => it could
        // only have been resolved by matching an _sd digest to a disclosure, i.e. it was selectively
        // disclosed. Present in the raw payload directly => mandatory-to-present, never withheld.
        try {
            path.select(rawIssuerPayload);
            return false;
        } catch (ClaimsPathPointerException notInRawPayload) {
            return true;
        }
    }

    @Override
    public boolean hasCryptographicHolderBinding() {
        return rawIssuerPayload.path("cnf").path("jwk").isObject();
    }

    @Override
    public boolean matchesMeta(CredentialQueryMeta meta) {
        return meta instanceof SdJwtVcMeta sdJwtVcMeta && sdJwtVcMeta.vctValues().contains(vct);
    }

    /**
     * The {@link Disclosure}s that must be included in a presentation for the given claims path to be
     * resolvable by the Verifier — i.e. every disclosure encountered while walking from the root to that
     * path, including any ancestor object/array levels that were themselves selectively disclosed
     * (recursive disclosure). Mandatory (always-present) path segments contribute no disclosures.
     *
     * <p>Only object-property disclosures ({@code [salt, name, value]}) are supported; the mdoc-style
     * array-element disclosure marker ({@code {"...": <digest>}}) is not used by any credential this
     * module issues/holds, so it isn't handled here.
     */
    List<Disclosure> disclosuresFor(ClaimsPathPointer path) {
        Map<String, Disclosure> byDigest = new HashMap<>();
        String hashAlg = rawIssuerPayload.path("_sd_alg").asText(HashAlgorithms.DEFAULT);
        for (Disclosure disclosure : issuanceForm.disclosures()) {
            byDigest.put(disclosure.digest(hashAlg), disclosure);
        }

        List<Disclosure> collected = new ArrayList<>();
        collectDisclosures(rawIssuerPayload, path.components(), byDigest, hashAlg, collected);
        return collected;
    }

    private static void collectDisclosures(
            JsonNode node, List<PathComponent> remainingPath, Map<String, Disclosure> byDigest, String hashAlg,
            List<Disclosure> collected) {
        if (remainingPath.isEmpty()) {
            return;
        }
        PathComponent component = remainingPath.get(0);
        List<PathComponent> rest = remainingPath.subList(1, remainingPath.size());

        switch (component) {
            case PathComponent.Key(String name) -> {
                if (node.isObject() && node.has(name)) {
                    collectDisclosures(node.get(name), rest, byDigest, hashAlg, collected);
                } else if (node.isObject() && node.has("_sd")) {
                    Disclosure match = findByClaimName(node.get("_sd"), name, byDigest);
                    if (match == null) {
                        throw new ClaimsPathPointerException("claim \"" + name + "\" not found (mandatory or disclosed)");
                    }
                    collected.add(match);
                    collectDisclosures(match.claimValue(), rest, byDigest, hashAlg, collected);
                } else {
                    throw new ClaimsPathPointerException("claims path pointer component \"" + name + "\" expects an object");
                }
            }
            case PathComponent.AllElements ignored -> {
                if (!node.isArray()) {
                    throw new ClaimsPathPointerException("claims path pointer component null expects an array");
                }
                node.forEach(element -> collectDisclosures(element, rest, byDigest, hashAlg, collected));
            }
            case PathComponent.Index(int index) -> {
                if (!node.isArray() || index >= node.size()) {
                    throw new ClaimsPathPointerException("claims path pointer index " + index + " not found");
                }
                collectDisclosures(node.get(index), rest, byDigest, hashAlg, collected);
            }
        }
    }

    private static Disclosure findByClaimName(JsonNode sdArray, String claimName, Map<String, Disclosure> byDigest) {
        for (JsonNode digestNode : sdArray) {
            Disclosure candidate = byDigest.get(digestNode.asText());
            if (candidate != null && candidate.claimName().isPresent() && candidate.claimName().get().equals(claimName)) {
                return candidate;
            }
        }
        return null;
    }
}
