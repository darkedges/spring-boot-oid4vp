package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQueryMeta;
import com.darkedges.oid4vp.core.dcql.MsoMdocMeta;
import com.darkedges.oid4vp.core.dcql.PathComponent;
import com.darkedges.oid4vp.core.dcql.eval.HeldCredential;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.security.interfaces.ECPublicKey;
import java.util.List;

/**
 * An {@code mso_mdoc} Credential as held by a Wallet: an issuer-signed {@code IssuerSigned} structure
 * ({@code nameSpaces} + {@code issuerAuth}) — reusable across many presentations, the way a real mDL's
 * issuer signature is, unlike the fresh-per-presentation {@code DeviceAuth} a
 * {@code PresentationBuilder} builds at presentation time.
 *
 * <p>Like {@code SdJwtVcHeldCredential}, this does <em>not</em> verify {@code IssuerAuth}'s signature at
 * parse time — that happens at presentation-verification time via {@link MdocVerifier}; a Wallet's local
 * credential store is trusted storage, not an adversarial input.
 */
public final class MdocHeldCredential implements HeldCredential {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String docType;
    private final Map nameSpaces;
    private final DataItem issuerAuth;
    private final JsonNode claimsView;
    private final ECPublicKey deviceKey;

    private MdocHeldCredential(String docType, Map nameSpaces, DataItem issuerAuth, JsonNode claimsView, ECPublicKey deviceKey) {
        this.docType = docType;
        this.nameSpaces = nameSpaces;
        this.issuerAuth = issuerAuth;
        this.claimsView = claimsView;
        this.deviceKey = deviceKey;
    }

    /** Parses a standalone CBOR-encoded {@code IssuerSigned} structure ({@code {nameSpaces, issuerAuth}}),
     * the same shape {@code DeviceResponse.documents[].issuerSigned} carries — this is exactly what a real
     * mDL issuer hands a Wallet at issuance time. */
    public static MdocHeldCredential parse(byte[] issuerSignedCbor) {
        Map issuerSigned = CborUtil.requireMap(CborUtil.decodeSingle(issuerSignedCbor));
        Map nameSpaces = CborUtil.requireMap(CborUtil.get(issuerSigned, "nameSpaces"));
        DataItem issuerAuth = CborUtil.get(issuerSigned, "issuerAuth");

        DataItem msoWrapper = CborUtil.decodeSingle(CoseSign1.parse(issuerAuth).payload());
        MobileSecurityObject mso = MobileSecurityObject.parse(CborUtil.unwrapEncodedCbor(msoWrapper));

        JsonNode claimsView = buildClaimsView(nameSpaces);
        return new MdocHeldCredential(mso.docType(), nameSpaces, issuerAuth, claimsView, mso.deviceKey());
    }

    private static JsonNode buildClaimsView(Map nameSpaces) {
        ObjectNode root = MAPPER.createObjectNode();
        for (DataItem namespaceKey : nameSpaces.getKeys()) {
            ObjectNode namespaceClaims = root.putObject(CborUtil.requireText(namespaceKey));
            for (DataItem wrapped : CborUtil.requireArray(nameSpaces.get(namespaceKey)).getDataItems()) {
                Map item = CborUtil.requireMap(CborUtil.unwrapEncodedCbor(wrapped));
                String elementIdentifier = CborUtil.requireText(CborUtil.get(item, "elementIdentifier"));
                namespaceClaims.set(elementIdentifier, CborUtil.toJson(CborUtil.get(item, "elementValue")));
            }
        }
        return root;
    }

    String docType() {
        return docType;
    }

    /** The raw, already-issuer-signed {@code nameSpaces} — a {@code PresentationBuilder} selects a subset
     * of each namespace's items for a given presentation rather than reconstructing them, since they're
     * already signed over as part of the MSO's digests. */
    Map issuerSignedNameSpaces() {
        return nameSpaces;
    }

    /** The already-issuer-signed {@code IssuerAuth} — reused verbatim across presentations. */
    DataItem issuerAuth() {
        return issuerAuth;
    }

    ECPublicKey deviceKey() {
        return deviceKey;
    }

    @Override
    public CredentialFormat format() {
        return CredentialFormat.MSO_MDOC;
    }

    @Override
    public JsonNode claimsView() {
        return claimsView;
    }

    @Override
    public boolean isSelectivelyDisclosable(ClaimsPathPointer path) {
        // Every mdoc namespace/element is disclosed by the Wallet's own choice at presentation time --
        // there's no "always mandatorily present" claim the way SD-JWT VC's non-`_sd` top-level claims are.
        return true;
    }

    @Override
    public boolean hasCryptographicHolderBinding() {
        // mdoc's deviceKeyInfo.deviceKey is a mandatory MSO field -- every mdoc has device binding.
        return true;
    }

    @Override
    public boolean matchesMeta(CredentialQueryMeta meta) {
        return meta instanceof MsoMdocMeta mdocMeta && mdocMeta.doctypeValue().equals(docType);
    }

    /** The mdoc-shape (2-component: namespace, element identifier) equivalent of
     * {@code SdJwtVcHeldCredential.disclosuresFor} — which {@code (namespace, elementIdentifier)} pairs a
     * given claims path resolves to, so a {@code PresentationBuilder} knows which
     * {@code IssuerSignedItem}s to include. */
    List<PathComponent> namespaceAndElementFor(ClaimsPathPointer path) {
        List<PathComponent> components = path.components();
        if (components.size() != 2
                || !(components.get(0) instanceof PathComponent.Key)
                || !(components.get(1) instanceof PathComponent.Key)) {
            throw new IllegalArgumentException(
                    "mso_mdoc claims paths must have exactly two Key components (namespace, elementIdentifier): " + components);
        }
        return components;
    }
}
