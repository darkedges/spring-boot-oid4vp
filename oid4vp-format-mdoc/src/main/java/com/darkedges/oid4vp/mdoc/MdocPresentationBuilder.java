package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.darkedges.oid4vp.core.dcql.ClaimsQuery;
import com.darkedges.oid4vp.core.dcql.PathComponent;
import com.darkedges.oid4vp.core.dcql.eval.ClaimSelection;

import java.security.PrivateKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Builds a presentation-time {@code DeviceResponse} from a held mdoc credential: reuses the
 * already-issuer-signed {@code IssuerSigned} data as-is (selecting only the disclosed namespace/element
 * subset, per {@link ClaimSelection} — mdoc's equivalent of SD-JWT VC choosing which Disclosures to
 * include), and signs a fresh {@code DeviceAuth} bound to this specific transaction via
 * {@link SessionTranscript}. The counterpart to {@link MdocVerifier}, on the Wallet side.
 */
public final class MdocPresentationBuilder {

    private MdocPresentationBuilder() {}

    public static String build(
            MdocHeldCredential credential,
            ClaimSelection claimSelection,
            PrivateKey devicePrivateKey,
            String clientId,
            String responseUri,
            String nonce,
            String mdocGeneratedNonce) {
        Map presentedNameSpaces = selectDisclosedItems(credential, claimSelection);

        Map issuerSigned = new Map();
        issuerSigned.put(new UnicodeString("nameSpaces"), presentedNameSpaces);
        issuerSigned.put(new UnicodeString("issuerAuth"), credential.issuerAuth());

        DataItem deviceNameSpacesBytes = MdocIssuer.wrapTag24(new Map());
        byte[] sessionTranscript = SessionTranscript.build(clientId, responseUri, nonce, mdocGeneratedNonce);
        byte[] deviceAuthentication = CborUtil.encode(new CborBuilder()
                .addArray()
                .add("DeviceAuthentication")
                .add(CborUtil.decodeSingle(sessionTranscript))
                .add(credential.docType())
                .add(deviceNameSpacesBytes)
                .end()
                .build()
                .get(0));
        DataItem deviceSignature = CoseSign1.sign1(devicePrivateKey, List.of(), null, deviceAuthentication);

        Map deviceAuth = new Map();
        deviceAuth.put(new UnicodeString("deviceSignature"), deviceSignature);
        Map deviceSigned = new Map();
        deviceSigned.put(new UnicodeString("nameSpaces"), deviceNameSpacesBytes);
        deviceSigned.put(new UnicodeString("deviceAuth"), deviceAuth);

        Map document = new Map();
        document.put(new UnicodeString("docType"), new UnicodeString(credential.docType()));
        document.put(new UnicodeString("issuerSigned"), issuerSigned);
        document.put(new UnicodeString("deviceSigned"), deviceSigned);

        Array documents = new Array();
        documents.add(document);
        Map deviceResponse = new Map();
        deviceResponse.put(new UnicodeString("version"), new UnicodeString("1.0"));
        deviceResponse.put(new UnicodeString("documents"), documents);
        deviceResponse.put(new UnicodeString("status"), new UnsignedInteger(0));

        return Base64.getUrlEncoder().withoutPadding().encodeToString(CborUtil.encode(deviceResponse));
    }

    private static Map selectDisclosedItems(MdocHeldCredential credential, ClaimSelection claimSelection) {
        Map available = credential.issuerSignedNameSpaces();
        if (claimSelection instanceof ClaimSelection.MandatoryOnly) {
            // No specific claims list requested -- mdoc has no "always mandatory" claim tier the way
            // SD-JWT VC's non-`_sd` top-level claims are, so disclose everything the Wallet holds.
            return available;
        }

        ClaimSelection.Selected selected = (ClaimSelection.Selected) claimSelection;
        java.util.Map<String, Set<String>> requestedElementsByNamespace = new LinkedHashMap<>();
        for (ClaimsQuery claim : selected.chosenClaims()) {
            List<PathComponent> components = credential.namespaceAndElementFor(claim.path());
            String namespace = ((PathComponent.Key) components.get(0)).name();
            String element = ((PathComponent.Key) components.get(1)).name();
            requestedElementsByNamespace.computeIfAbsent(namespace, k -> new LinkedHashSet<>()).add(element);
        }

        Map result = new Map();
        for (DataItem namespaceKey : available.getKeys()) {
            String namespace = CborUtil.requireText(namespaceKey);
            Set<String> wantedElements = requestedElementsByNamespace.get(namespace);
            if (wantedElements == null) {
                continue;
            }
            Array filtered = new Array();
            for (DataItem wrapped : CborUtil.requireArray(available.get(namespaceKey)).getDataItems()) {
                Map item = CborUtil.requireMap(CborUtil.unwrapEncodedCbor(wrapped));
                String elementIdentifier = CborUtil.requireText(CborUtil.get(item, "elementIdentifier"));
                if (wantedElements.contains(elementIdentifier)) {
                    filtered.add(wrapped);
                }
            }
            result.put(new UnicodeString(namespace), filtered);
        }
        return result;
    }
}
