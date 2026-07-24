package com.darkedges.oid4vp.mdoc;

import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.core.response.PresentationVerificationParams;
import com.darkedges.oid4vp.core.response.PresentationVerifier;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * The {@code mso_mdoc} (ISO/IEC 18013-5) presentation verifier: parses a base64url {@code DeviceResponse},
 * verifies {@code IssuerAuth} (a COSE_Sign1 over the {@link MobileSecurityObject}), digest-verifies each
 * disclosed {@code IssuerSignedItem}, and verifies {@code DeviceAuth}'s binding to this transaction via a
 * reconstructed {@link SessionTranscript}/{@code OID4VPHandover} and {@code DeviceAuthentication}
 * structure — mdoc's structural equivalent of SD-JWT VC's Key Binding JWT, except device binding isn't
 * optional the way {@code require_cryptographic_holder_binding} is for SD-JWT: it's always verified here.
 *
 * <p>Only the first {@code Document} in {@code DeviceResponse.documents} is considered — this project (like
 * its DCQL modeling generally) doesn't yet support a single mdoc presentation satisfying multiple Credential
 * Queries. Only {@code deviceSignature} (COSE_Sign1) is supported for {@code DeviceAuth}; MAC-based device
 * authentication ({@code deviceMac}, COSE_Mac0) is not implemented.
 */
public final class MdocVerifier implements PresentationVerifier {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public CredentialFormat format() {
        return CredentialFormat.MSO_MDOC;
    }

    @Override
    public VerifiedPresentation verify(PresentationEntry presentation, PresentationVerificationParams params) {
        if (!(presentation instanceof PresentationEntry.StringPresentation(String serialized))) {
            throw new MdocVerificationException("mso_mdoc presentation must be a string, was: " + presentation);
        }

        Map deviceResponse = CborUtil.requireMap(CborUtil.decodeSingle(base64UrlDecode(serialized)));
        Array documents = CborUtil.requireArray(CborUtil.get(deviceResponse, "documents"));
        if (documents.getDataItems().isEmpty()) {
            throw new MdocVerificationException("DeviceResponse has no documents");
        }
        Map document = CborUtil.requireMap(documents.getDataItems().get(0));
        String docType = CborUtil.requireText(CborUtil.get(document, "docType"));

        Map issuerSigned = CborUtil.requireMap(CborUtil.get(document, "issuerSigned"));
        CoseSign1 issuerAuth = CoseSign1.parse(CborUtil.get(issuerSigned, "issuerAuth"));

        ECPublicKey issuerKey = resolveIssuerKey(docType, issuerAuth.x5chain(), params);
        issuerAuth.verify(issuerKey);

        DataItem msoWrapper = CborUtil.decodeSingle(issuerAuth.payload());
        MobileSecurityObject mso = MobileSecurityObject.parse(CborUtil.unwrapEncodedCbor(msoWrapper));

        if (!mso.docType().equals(docType)) {
            throw new MdocVerificationException(
                    "MSO docType \"" + mso.docType() + "\" does not match Document docType \"" + docType + "\"");
        }
        checkValidity(mso, params);

        ObjectNode verifiedClaims = verifyDisclosedItems(issuerSigned, mso);

        verifyDeviceAuth(document, docType, mso, params);

        JsonNode holderKeyConfirmed = toPublicJwk(mso.deviceKey());
        return new VerifiedPresentation(params.query().id(), CredentialFormat.MSO_MDOC, verifiedClaims, Optional.of(holderKeyConfirmed));
    }

    private ECPublicKey resolveIssuerKey(String docType, List<String> certificateChain, PresentationVerificationParams params) {
        // mdoc has no separate "issuer" identifier claim the way SD-JWT VC's "iss" is; docType is the
        // closest available label, used purely for diagnostics/logging by resolver implementations that
        // want it — trust here is expected to come from certificateChain (the MSO's x5chain), same as
        // SD-JWT VC's x5c-based resolution.
        JsonNode jwk = params.issuerKeyResolver().resolve(docType, Optional.empty(), certificateChain)
                .orElseThrow(() -> new MdocVerificationException("no issuer key found for docType \"" + docType + "\""));
        try {
            return ECKey.parse(jwk.toString()).toECPublicKey();
        } catch (ParseException | JOSEException e) {
            throw new MdocVerificationException("resolved issuer key is not a valid EC public key", e);
        }
    }

    private static void checkValidity(MobileSecurityObject mso, PresentationVerificationParams params) {
        Instant now = params.clock().instant();
        if (now.isBefore(mso.validFrom())) {
            throw new MdocVerificationException("MSO is not yet valid: validFrom=" + mso.validFrom() + ", now=" + now);
        }
        if (now.isAfter(mso.validUntil())) {
            throw new MdocVerificationException("MSO has expired: validUntil=" + mso.validUntil() + ", now=" + now);
        }
    }

    private static ObjectNode verifyDisclosedItems(Map issuerSigned, MobileSecurityObject mso) {
        MessageDigest digest = digestFor(mso.digestAlgorithm());
        ObjectNode claims = MAPPER.createObjectNode();

        Map nameSpaces = CborUtil.requireMap(CborUtil.get(issuerSigned, "nameSpaces"));
        for (DataItem namespaceKey : nameSpaces.getKeys()) {
            String namespace = CborUtil.requireText(namespaceKey);
            java.util.Map<Long, byte[]> expectedDigests = mso.valueDigests().get(namespace);
            if (expectedDigests == null) {
                throw new MdocVerificationException("MSO has no digests for disclosed namespace \"" + namespace + "\"");
            }

            ObjectNode namespaceClaims = claims.putObject(namespace);
            for (DataItem wrapped : CborUtil.requireArray(nameSpaces.get(namespaceKey)).getDataItems()) {
                byte[] actualDigest = digest.digest(CborUtil.encode(wrapped));
                Map item = CborUtil.requireMap(CborUtil.unwrapEncodedCbor(wrapped));

                long digestId = CborUtil.requireLong(CborUtil.get(item, "digestID"));
                String elementIdentifier = CborUtil.requireText(CborUtil.get(item, "elementIdentifier"));
                byte[] expectedDigest = expectedDigests.get(digestId);
                if (expectedDigest == null) {
                    throw new MdocVerificationException(
                            "MSO has no digest for digestID " + digestId + " (\"" + elementIdentifier + "\" in \"" + namespace + "\")");
                }
                if (!MessageDigest.isEqual(expectedDigest, actualDigest)) {
                    throw new MdocVerificationException(
                            "digest mismatch for \"" + elementIdentifier + "\" in \"" + namespace + "\" -- disclosed value does not match the signed MSO");
                }

                namespaceClaims.set(elementIdentifier, CborUtil.toJson(CborUtil.get(item, "elementValue")));
            }
        }
        return claims;
    }

    private void verifyDeviceAuth(Map document, String docType, MobileSecurityObject mso, PresentationVerificationParams params) {
        String mdocGeneratedNonce = params.mdocGeneratedNonce()
                .orElseThrow(() -> new MdocVerificationException(
                        "no mdocGeneratedNonce available -- mso_mdoc presentations require an encrypted "
                                + "response (direct_post.jwt/dc_api.jwt) carrying it in the JWE \"apu\" header"));
        byte[] sessionTranscript = SessionTranscript.build(
                params.clientId(), params.responseUri(), params.expectedNonce(), mdocGeneratedNonce);

        Map deviceSigned = CborUtil.requireMap(CborUtil.get(document, "deviceSigned"));
        DataItem deviceNameSpacesBytes = CborUtil.get(deviceSigned, "nameSpaces");
        Map deviceAuth = CborUtil.requireMap(CborUtil.get(deviceSigned, "deviceAuth"));
        DataItem deviceSignatureItem = CborUtil.getOrNull(deviceAuth, "deviceSignature");
        if (deviceSignatureItem == null) {
            throw new MdocVerificationException("deviceAuth.deviceMac is not supported -- only deviceSignature (COSE_Sign1) is");
        }

        byte[] deviceAuthentication = CborUtil.encode(new co.nstant.in.cbor.CborBuilder()
                .addArray()
                .add("DeviceAuthentication")
                .add(CborUtil.decodeSingle(sessionTranscript))
                .add(docType)
                .add(deviceNameSpacesBytes)
                .end()
                .build()
                .get(0));

        CoseSign1.parse(deviceSignatureItem).verifyDetached(mso.deviceKey(), deviceAuthentication);
    }

    private static MessageDigest digestFor(String digestAlgorithm) {
        String javaName = switch (digestAlgorithm) {
            case "SHA-256", "SHA-384", "SHA-512" -> digestAlgorithm;
            default -> throw new MdocVerificationException("unsupported MSO digestAlgorithm: " + digestAlgorithm);
        };
        try {
            return MessageDigest.getInstance(javaName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static JsonNode toPublicJwk(ECPublicKey deviceKey) {
        try {
            ECKey jwk = new ECKey.Builder(com.nimbusds.jose.jwk.Curve.P_256, deviceKey).build();
            return MAPPER.readTree(jwk.toJSONString());
        } catch (Exception e) {
            throw new MdocVerificationException("failed to serialize the device key as a JWK", e);
        }
    }

    private static byte[] base64UrlDecode(String value) {
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            // Some Wallets omit padding inconsistently; retry with padding restored before giving up.
            int padding = (4 - value.length() % 4) % 4;
            try {
                return Base64.getUrlDecoder().decode(value + "=".repeat(padding));
            } catch (IllegalArgumentException e2) {
                throw new MdocVerificationException("mso_mdoc presentation is not valid base64url", e2);
            }
        }
    }

}
