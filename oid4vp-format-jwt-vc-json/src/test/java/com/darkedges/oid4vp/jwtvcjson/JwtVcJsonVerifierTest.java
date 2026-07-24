package com.darkedges.oid4vp.jwtvcjson;

import com.darkedges.oid4vp.core.dcql.ClaimsPathPointer;
import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.darkedges.oid4vp.core.dcql.JwtVcMeta;
import com.darkedges.oid4vp.core.response.AudienceMismatchException;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.NonceMismatchException;
import com.darkedges.oid4vp.core.response.PresentationEntry;
import com.darkedges.oid4vp.core.response.PresentationVerificationParams;
import com.darkedges.oid4vp.core.response.VerifiedPresentation;
import com.darkedges.oid4vp.testfixtures.FixtureLoader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Builds a real holder-signed VP-JWT wrapping a real issuer-signed VC-JWT — using the exact claim values
 * from {@code docs/1.1/examples/credentials/jwt_vc.json} and {@code docs/1.1/examples/response/jwt_vc.json}
 * (whose own {@code vp.verifiableCredential[0]} is an elided {@code "eyJhb...ssw5c"} placeholder, so it
 * can't be used directly as a signed test vector) — and verifies it end-to-end.
 */
class JwtVcJsonVerifierTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ISSUER = "https://example.gov/issuers/565049";
    private static final String HOLDER = "did:example:ebfeb1f712ebc6f1c276e12ec21";
    private static final String AUDIENCE = "x509_san_dns:client.example.org";
    private static final String NONCE = "n-0S6_WzA2Mj";

    private static Clock fixedClock() {
        return Clock.fixed(Instant.ofEpochSecond(1541493724L), ZoneOffset.UTC);
    }

    private static SignedJWT signedVc(ECKey issuerKey) throws Exception {
        JsonNode fixture = FixtureLoader.readExampleJson("credentials/jwt_vc.json");
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(HOLDER)
                .claim("jti", fixture.get("jti").asText())
                .issueTime(Date.from(Instant.ofEpochSecond(fixture.get("nbf").asLong())))
                .claim("vc", MAPPER.convertValue(fixture.get("vc"), Map.class))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        jwt.sign(new ECDSASigner(issuerKey));
        return jwt;
    }

    private static SignedJWT signedVp(ECKey holderKey, SignedJWT vc, String nonce, String aud) throws Exception {
        ObjectNode vp = MAPPER.createObjectNode();
        vp.putArray("@context").add("https://www.w3.org/2018/credentials/v1");
        vp.putArray("type").add("VerifiablePresentation");
        vp.putArray("verifiableCredential").add(vc.serialize());

        Instant iat = fixedClock().instant();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(HOLDER)
                .claim("jti", "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5")
                .claim("aud", aud)
                .issueTime(Date.from(iat))
                .notBeforeTime(Date.from(iat))
                .expirationTime(Date.from(iat.plusSeconds(3600)))
                .claim("nonce", nonce)
                .claim("vp", MAPPER.convertValue(vp, Map.class))
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.ES256), claims);
        jwt.sign(new ECDSASigner(holderKey));
        return jwt;
    }

    private static IssuerKeyResolver resolverFor(ECKey issuerKey, ECKey holderKey) throws Exception {
        JsonNode issuerJwk = MAPPER.readTree(issuerKey.toPublicJWK().toJSONString());
        JsonNode holderJwk = MAPPER.readTree(holderKey.toPublicJWK().toJSONString());
        return (issuer, keyId, certificateChain) -> switch (issuer) {
            case ISSUER -> Optional.of(issuerJwk);
            case HOLDER -> Optional.of(holderJwk);
            default -> Optional.empty();
        };
    }

    private static CredentialQuery query() {
        return CredentialQuery.builder("example_jwt_vc", CredentialFormat.JWT_VC_JSON)
                .meta(new JwtVcMeta(List.of(List.of("IDCredential"))))
                .claims(List.of(
                        com.darkedges.oid4vp.core.dcql.ClaimsQuery.of(null, ClaimsPathPointer.of("credentialSubject", "family_name")),
                        com.darkedges.oid4vp.core.dcql.ClaimsQuery.of(null, ClaimsPathPointer.of("credentialSubject", "given_name"))))
                .build();
    }

    @Test
    void verifiesTheWrappedCredentialAndExposesCredentialSubjectClaims() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).generate();
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();

        SignedJWT vc = signedVc(issuerKey);
        SignedJWT vp = signedVp(holderKey, vc, NONCE, AUDIENCE);

        PresentationVerificationParams params = new PresentationVerificationParams(
                query(), NONCE, AUDIENCE, AUDIENCE, "https://verifier.example.org/response", Optional.empty(),
                resolverFor(issuerKey, holderKey), fixedClock());

        VerifiedPresentation result = new JwtVcJsonVerifier().verify(
                new PresentationEntry.StringPresentation(vp.serialize()), params);

        assertThat(result.credentialQueryId()).isEqualTo("example_jwt_vc");
        assertThat(result.format()).isEqualTo(CredentialFormat.JWT_VC_JSON);
        assertThat(result.holderKeyConfirmed()).isPresent();

        JsonNode credentialSubject = result.verifiedClaims().get("credentialSubject");
        assertThat(credentialSubject.get("given_name").asText()).isEqualTo("Max");
        assertThat(credentialSubject.get("family_name").asText()).isEqualTo("Mustermann");

        // DCQL claims paths from docs/1.1/examples/request/dcql_jwt_vc.json resolve correctly.
        assertThat(ClaimsPathPointer.of("credentialSubject", "family_name").select(result.verifiedClaims()))
                .extracting(JsonNode::asText).containsExactly("Mustermann");
    }

    @Test
    void rejectsWrongNonce() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).generate();
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();
        SignedJWT vc = signedVc(issuerKey);
        SignedJWT vp = signedVp(holderKey, vc, NONCE, AUDIENCE);

        PresentationVerificationParams params = new PresentationVerificationParams(
                query(), "wrong-nonce", AUDIENCE, AUDIENCE, "https://verifier.example.org/response", Optional.empty(),
                resolverFor(issuerKey, holderKey), fixedClock());

        assertThatThrownBy(() -> new JwtVcJsonVerifier().verify(new PresentationEntry.StringPresentation(vp.serialize()), params))
                .isInstanceOf(NonceMismatchException.class);
    }

    @Test
    void rejectsWrongAudience() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).generate();
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();
        SignedJWT vc = signedVc(issuerKey);
        SignedJWT vp = signedVp(holderKey, vc, NONCE, AUDIENCE);

        PresentationVerificationParams params = new PresentationVerificationParams(
                query(), NONCE, "someone-else", "someone-else", "https://verifier.example.org/response", Optional.empty(),
                resolverFor(issuerKey, holderKey), fixedClock());

        assertThatThrownBy(() -> new JwtVcJsonVerifier().verify(new PresentationEntry.StringPresentation(vp.serialize()), params))
                .isInstanceOf(AudienceMismatchException.class);
    }

    @Test
    void rejectsATamperedInnerCredentialSignature() throws Exception {
        ECKey issuerKey = new ECKeyGenerator(Curve.P_256).generate();
        ECKey wrongIssuerKey = new ECKeyGenerator(Curve.P_256).generate();
        ECKey holderKey = new ECKeyGenerator(Curve.P_256).generate();
        SignedJWT vc = signedVc(issuerKey);
        SignedJWT vp = signedVp(holderKey, vc, NONCE, AUDIENCE);

        // Resolver returns the WRONG issuer key, simulating a credential whose signature doesn't match
        // what's on file for that issuer.
        JsonNode wrongJwk = MAPPER.readTree(wrongIssuerKey.toPublicJWK().toJSONString());
        JsonNode holderJwk = MAPPER.readTree(holderKey.toPublicJWK().toJSONString());
        IssuerKeyResolver resolver = (issuer, keyId, certificateChain) -> switch (issuer) {
            case ISSUER -> Optional.of(wrongJwk);
            case HOLDER -> Optional.of(holderJwk);
            default -> Optional.empty();
        };

        PresentationVerificationParams params = new PresentationVerificationParams(
                query(), NONCE, AUDIENCE, AUDIENCE, "https://verifier.example.org/response", Optional.empty(), resolver, fixedClock());

        assertThatThrownBy(() -> new JwtVcJsonVerifier().verify(new PresentationEntry.StringPresentation(vp.serialize()), params))
                .isInstanceOf(JwtVcJsonVerificationException.class);
    }
}
