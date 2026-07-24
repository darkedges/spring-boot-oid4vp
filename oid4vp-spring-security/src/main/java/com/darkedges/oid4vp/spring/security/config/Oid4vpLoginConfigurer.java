package com.darkedges.oid4vp.spring.security.config;

import com.darkedges.oid4vp.core.dcql.CredentialFormat;
import com.darkedges.oid4vp.core.request.RequestObjectSigningKeyResolver;
import com.darkedges.oid4vp.core.request.TokenEndpointClient;
import com.darkedges.oid4vp.core.response.IssuerKeyResolver;
import com.darkedges.oid4vp.core.response.PresentationVerifier;
import com.darkedges.oid4vp.core.response.ResponseDecryptionKeyResolver;
import com.darkedges.oid4vp.spring.security.authentication.Oid4vpAuthorizationResponseAuthenticationProvider;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.spring.security.web.InMemoryOid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.InMemoryOid4vpEphemeralEncryptionKeyRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationCodeCallbackFilter;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationRequestService;
import com.darkedges.oid4vp.spring.security.web.Oid4vpEphemeralEncryptionKeyRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationResponseAuthenticationConverter;
import com.darkedges.oid4vp.spring.security.web.Oid4vpAuthorizationResponseAuthenticationFilter;
import com.darkedges.oid4vp.spring.security.web.Oid4vpDcApiAuthenticationConverter;
import com.darkedges.oid4vp.spring.security.web.Oid4vpRequestObjectFilter;
import com.darkedges.oid4vp.spring.security.web.Oid4vpSameDeviceAuthenticationSuccessHandler;
import com.darkedges.oid4vp.spring.security.web.Oid4vpTransactionResultFilter;
import com.darkedges.oid4vp.spring.security.web.Oid4vpTransactionResultRepository;
import com.darkedges.oid4vp.spring.security.web.Oid4vpWalletInvocationFilter;
import com.darkedges.oid4vp.verifier.AuthorizationResponseValidator;
import com.nimbusds.jose.JWSAlgorithm;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * {@code HttpSecurity} DSL extension registering the OpenID4VP Verifier {@code direct_post} response
 * endpoint, analogous in shape to {@code oauth2Login()}.
 *
 * <p>Builds its own self-contained {@link ProviderManager} (rather than contributing to the shared
 * {@code AuthenticationManager}), so the response filter doesn't depend on the timing of global
 * authentication-manager composition elsewhere in the security configuration.
 */
public final class Oid4vpLoginConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<Oid4vpLoginConfigurer<H>, H> {

    private Oid4vpRelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
    private Oid4vpAuthorizationRequestRepository authorizationRequestRepository = new InMemoryOid4vpAuthorizationRequestRepository();
    private Oid4vpEphemeralEncryptionKeyRepository ephemeralEncryptionKeyRepository = new InMemoryOid4vpEphemeralEncryptionKeyRepository();
    private final Map<CredentialFormat, PresentationVerifier> presentationVerifiers = new HashMap<>();
    private IssuerKeyResolver issuerKeyResolver;
    private ResponseDecryptionKeyResolver responseDecryptionKeyResolver;
    private Clock clock = Clock.systemUTC();
    private RequestMatcher requestMatcher = Oid4vpAuthorizationResponseAuthenticationFilter.defaultRequestMatcher();
    private RequestMatcher dcApiRequestMatcher = Oid4vpAuthorizationResponseAuthenticationFilter.defaultDcApiRequestMatcher();
    private boolean dcApiEnabled = true;
    private Duration requestTtl = Duration.ofMinutes(10);
    private RequestObjectSigningKeyResolver requestObjectSigningKeyResolver;
    private JWSAlgorithm requestObjectSigningAlgorithm = JWSAlgorithm.ES256;
    private RequestMatcher requestObjectRequestMatcher =
            PathPatternRequestMatcher.pathPattern(Oid4vpRequestObjectFilter.DEFAULT_REQUEST_URI_PATTERN);
    private Oid4vpTransactionResultRepository transactionResultRepository;
    private String sameDeviceResultBaseUri;
    private RequestMatcher transactionResultRequestMatcher =
            PathPatternRequestMatcher.pathPattern(Oid4vpTransactionResultFilter.DEFAULT_RESULT_URI_PATTERN);
    private String sameDeviceResultRedirectUri;
    private String walletInvocationRequestUriBase;
    private RequestMatcher walletInvocationRequestMatcher =
            PathPatternRequestMatcher.pathPattern(Oid4vpWalletInvocationFilter.DEFAULT_INVOKE_URI_PATTERN);
    private TokenEndpointClient tokenEndpointClient;
    private String authorizationCodeSuccessRedirectUri;
    private RequestMatcher authorizationCodeCallbackRequestMatcher = Oid4vpAuthorizationCodeCallbackFilter.defaultRequestMatcher();

    public Oid4vpLoginConfigurer<H> relyingPartyRegistrationRepository(Oid4vpRelyingPartyRegistrationRepository repository) {
        this.relyingPartyRegistrationRepository = repository;
        return this;
    }

    public Oid4vpRelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
        return relyingPartyRegistrationRepository;
    }

    public Oid4vpLoginConfigurer<H> authorizationRequestRepository(Oid4vpAuthorizationRequestRepository repository) {
        this.authorizationRequestRepository = repository;
        return this;
    }

    /** Only matters for {@code direct_post.jwt}/{@code dc_api.jwt} registrations (see
     * {@code Oid4vpAuthorizationRequestService}, which generates a fresh response-encryption key per
     * request here and saves it into this repository). If the application also builds its
     * {@code ResponseDecryptionKeyResolver} from a shared instance of this repository — as it must, to
     * find the keys generated here — pass that <em>same</em> instance to both places. */
    public Oid4vpLoginConfigurer<H> ephemeralEncryptionKeyRepository(Oid4vpEphemeralEncryptionKeyRepository repository) {
        this.ephemeralEncryptionKeyRepository = repository;
        return this;
    }

    public Oid4vpLoginConfigurer<H> presentationVerifier(PresentationVerifier verifier) {
        this.presentationVerifiers.put(verifier.format(), verifier);
        return this;
    }

    public Oid4vpLoginConfigurer<H> issuerKeyResolver(IssuerKeyResolver resolver) {
        this.issuerKeyResolver = resolver;
        return this;
    }

    /** Enables {@code direct_post.jwt} (encrypted response) support by supplying the Verifier's private
     * response-decryption keys, per relying-party registration. */
    public Oid4vpLoginConfigurer<H> responseDecryptionKeyResolver(ResponseDecryptionKeyResolver resolver) {
        this.responseDecryptionKeyResolver = resolver;
        return this;
    }

    public Oid4vpLoginConfigurer<H> clock(Clock clock) {
        this.clock = clock;
        return this;
    }

    /** Overrides the default {@code /login/oid4vp/direct-post/{registrationId}} POST path pattern. */
    public Oid4vpLoginConfigurer<H> responseUriPattern(String pathPattern) {
        this.requestMatcher = PathPatternRequestMatcher.pathPattern(HttpMethod.POST, pathPattern);
        return this;
    }

    /** Overrides the default {@code /login/oid4vp/dc-api/{registrationId}} POST path pattern used for
     * relayed Digital Credentials API results. */
    public Oid4vpLoginConfigurer<H> dcApiResponseUriPattern(String pathPattern) {
        this.dcApiRequestMatcher = PathPatternRequestMatcher.pathPattern(HttpMethod.POST, pathPattern);
        return this;
    }

    /** Disables registering the Digital Credentials API relay endpoint (enabled by default). */
    public Oid4vpLoginConfigurer<H> disableDcApi() {
        this.dcApiEnabled = false;
        return this;
    }

    /** How long an issued Authorization Request's context is kept while awaiting the Wallet's response
     * (used both for response correlation and, indirectly, for how long a hosted request_uri stays valid). */
    public Oid4vpLoginConfigurer<H> requestTtl(Duration requestTtl) {
        this.requestTtl = requestTtl;
        return this;
    }

    /**
     * Enables hosting the Authorization Request by reference ({@code request_uri}, GET and
     * {@code request_uri_method=post}) by supplying the Verifier's private Request Object signing keys,
     * per relying-party registration. Requires {@link #relyingPartyRegistrationRepository} to also be
     * configured. Not enabled unless a resolver is supplied here.
     */
    public Oid4vpLoginConfigurer<H> requestObjectSigningKeyResolver(RequestObjectSigningKeyResolver resolver) {
        this.requestObjectSigningKeyResolver = resolver;
        return this;
    }

    public Oid4vpLoginConfigurer<H> requestObjectSigningAlgorithm(JWSAlgorithm algorithm) {
        this.requestObjectSigningAlgorithm = algorithm;
        return this;
    }

    /** Overrides the default {@code /oid4vp/request/{registrationId}} path pattern (GET and POST) used
     * to host the Request Object by reference. */
    public Oid4vpLoginConfigurer<H> requestUriPattern(String pathPattern) {
        this.requestObjectRequestMatcher = PathPatternRequestMatcher.pathPattern(pathPattern);
        return this;
    }

    /**
     * Enables the same-device {@code response_code}/{@code redirect_uri} handoff (OpenID4VP 1.1,
     * "Response Mode direct_post" reference design): every issued Authorization Request gets a
     * {@code transactionId}; on a successful {@code direct_post} response, the Wallet is told to redirect
     * the End-User's browser to {@code <resultBaseUri>/<transactionId>?response_code=...}, which
     * {@link Oid4vpTransactionResultFilter} serves to complete authentication for that browser session.
     *
     * @param resultBaseUri e.g. {@code "https://verifier.example.org/oid4vp/result"} — must be an
     *                      absolute URI reachable by the End-User's browser.
     */
    public Oid4vpLoginConfigurer<H> sameDeviceHandoff(Oid4vpTransactionResultRepository repository, String resultBaseUri) {
        this.transactionResultRepository = repository;
        this.sameDeviceResultBaseUri = resultBaseUri;
        return this;
    }

    /** Overrides the default {@code /oid4vp/result/{transactionId}} path pattern used to complete the
     * same-device handoff. Must stay consistent with the path implied by the {@code resultBaseUri}
     * passed to {@link #sameDeviceHandoff}. */
    public Oid4vpLoginConfigurer<H> sameDeviceResultUriPattern(String pathPattern) {
        this.transactionResultRequestMatcher = PathPatternRequestMatcher.pathPattern(pathPattern);
        return this;
    }

    /**
     * Once the same-device handoff completes and the {@code SecurityContext} is established, redirect the
     * End-User's browser here instead of writing the default {@code {}} JSON body — e.g. back to a demo
     * page so it can re-check {@code /profile} and show a signed-in state. Relative URIs are resolved
     * against the Verifier's own origin.
     */
    public Oid4vpLoginConfigurer<H> sameDeviceResultRedirectUri(String redirectUri) {
        this.sameDeviceResultRedirectUri = redirectUri;
        return this;
    }

    /**
     * Enables {@code GET /oid4vp/invoke/{registrationId}} ({@link Oid4vpWalletInvocationFilter}):
     * redirects the End-User's browser to a Wallet's {@code authorization_endpoint} (configured per
     * relying-party registration, not accepted as a request parameter — see
     * {@code Oid4vpRelyingPartyRegistration.walletAuthorizationEndpoint}) with {@code client_id} and
     * {@code request_uri} attached. Requires {@link #relyingPartyRegistrationRepository} and
     * {@link #requestObjectSigningKeyResolver} to also be configured — an unsigned request has nothing a
     * real Wallet would trust.
     *
     * @param requestUriBase e.g. {@code "https://verifier.example.org/oid4vp/request"} — must match
     *                       wherever {@link Oid4vpRequestObjectFilter} is actually hosted (see
     *                       {@link #requestUriPattern}).
     */
    public Oid4vpLoginConfigurer<H> walletInvocation(String requestUriBase) {
        this.walletInvocationRequestUriBase = requestUriBase;
        return this;
    }

    /** Overrides the default {@code /oid4vp/invoke/{registrationId}} path pattern used by
     * {@link #walletInvocation}. */
    public Oid4vpLoginConfigurer<H> walletInvocationUriPattern(String pathPattern) {
        this.walletInvocationRequestMatcher = PathPatternRequestMatcher.pathPattern(pathPattern);
        return this;
    }

    /**
     * Enables {@code GET /oid4vp/callback/{registrationId}} ({@link Oid4vpAuthorizationCodeCallbackFilter}):
     * completes the OAuth 2.0 Authorization Code Grant ({@code response_type=code}) flow for registrations
     * configured with a {@code CodeFlowConfig} — receives the Wallet's {@code ?code=...&state=...}
     * redirect, exchanges {@code code} for a Token Response via the supplied client, and authenticates the
     * resulting {@code vp_token} through the same validation path as {@code direct_post}. Requires
     * {@link #relyingPartyRegistrationRepository} to also be configured.
     */
    public Oid4vpLoginConfigurer<H> authorizationCodeCallback(TokenEndpointClient tokenEndpointClient) {
        this.tokenEndpointClient = tokenEndpointClient;
        return this;
    }

    /** Overrides the default {@code /oid4vp/callback/{registrationId}} path pattern used by
     * {@link #authorizationCodeCallback}. */
    public Oid4vpLoginConfigurer<H> authorizationCodeCallbackUriPattern(String pathPattern) {
        this.authorizationCodeCallbackRequestMatcher = PathPatternRequestMatcher.pathPattern(HttpMethod.GET, pathPattern);
        return this;
    }

    /**
     * Once the Authorization Code Grant's token exchange completes and the {@code SecurityContext} is
     * established, redirect the End-User's browser here instead of writing the default {@code {}} JSON
     * body — same idea as {@link #sameDeviceResultRedirectUri}.
     */
    public Oid4vpLoginConfigurer<H> authorizationCodeSuccessRedirectUri(String redirectUri) {
        this.authorizationCodeSuccessRedirectUri = redirectUri;
        return this;
    }

    @Override
    public void init(H http) {
        if (issuerKeyResolver == null) {
            throw new IllegalStateException("issuerKeyResolver must be configured via .issuerKeyResolver(...)");
        }
        if (presentationVerifiers.isEmpty()) {
            throw new IllegalStateException("at least one presentationVerifier must be configured via .presentationVerifier(...)");
        }
        if (walletInvocationRequestUriBase != null && relyingPartyRegistrationRepository == null) {
            throw new IllegalStateException("relyingPartyRegistrationRepository must be configured to use .walletInvocation(...)");
        }
        if (tokenEndpointClient != null && relyingPartyRegistrationRepository == null) {
            throw new IllegalStateException("relyingPartyRegistrationRepository must be configured to use .authorizationCodeCallback(...)");
        }
    }

    @Override
    public void configure(H http) {
        AuthorizationResponseValidator validator = new AuthorizationResponseValidator(Map.copyOf(presentationVerifiers));
        ProviderManager authenticationManager = new ProviderManager(
                new Oid4vpAuthorizationResponseAuthenticationProvider(
                        validator, issuerKeyResolver, requestObjectSigningKeyResolver, clock));

        Oid4vpAuthorizationResponseAuthenticationConverter converter = new Oid4vpAuthorizationResponseAuthenticationConverter(
                authorizationRequestRepository, requestMatcher, responseDecryptionKeyResolver);
        Oid4vpAuthorizationResponseAuthenticationFilter filter =
                new Oid4vpAuthorizationResponseAuthenticationFilter(authenticationManager, requestMatcher, converter);
        if (transactionResultRepository != null) {
            filter.setAuthenticationSuccessHandler(
                    new Oid4vpSameDeviceAuthenticationSuccessHandler(transactionResultRepository, sameDeviceResultBaseUri));
        }
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

        if (dcApiEnabled) {
            Oid4vpDcApiAuthenticationConverter dcApiConverter = new Oid4vpDcApiAuthenticationConverter(
                    authorizationRequestRepository, dcApiRequestMatcher, responseDecryptionKeyResolver);
            Oid4vpAuthorizationResponseAuthenticationFilter dcApiFilter = new Oid4vpAuthorizationResponseAuthenticationFilter(
                    authenticationManager, dcApiRequestMatcher, dcApiConverter);
            http.addFilterBefore(dcApiFilter, UsernamePasswordAuthenticationFilter.class);
        }

        if (requestObjectSigningKeyResolver != null) {
            if (relyingPartyRegistrationRepository == null) {
                throw new IllegalStateException(
                        "relyingPartyRegistrationRepository must be configured to host request objects via requestObjectSigningKeyResolver(...)");
            }
            Oid4vpAuthorizationRequestService requestService = new Oid4vpAuthorizationRequestService(
                    relyingPartyRegistrationRepository, authorizationRequestRepository,
                    ephemeralEncryptionKeyRepository, clock, requestTtl);
            Oid4vpRequestObjectFilter requestObjectFilter = new Oid4vpRequestObjectFilter(
                    requestObjectRequestMatcher, requestService, requestObjectSigningKeyResolver, requestObjectSigningAlgorithm);
            http.addFilterBefore(requestObjectFilter, UsernamePasswordAuthenticationFilter.class);
        }

        if (transactionResultRepository != null) {
            Oid4vpTransactionResultFilter transactionResultFilter =
                    new Oid4vpTransactionResultFilter(transactionResultRequestMatcher, transactionResultRepository, sameDeviceResultRedirectUri);
            http.addFilterBefore(transactionResultFilter, UsernamePasswordAuthenticationFilter.class);
        }

        if (walletInvocationRequestUriBase != null) {
            Oid4vpWalletInvocationFilter walletInvocationFilter = new Oid4vpWalletInvocationFilter(
                    walletInvocationRequestMatcher, relyingPartyRegistrationRepository, walletInvocationRequestUriBase);
            http.addFilterBefore(walletInvocationFilter, UsernamePasswordAuthenticationFilter.class);
        }

        if (tokenEndpointClient != null) {
            Oid4vpAuthorizationCodeCallbackFilter authorizationCodeCallbackFilter = new Oid4vpAuthorizationCodeCallbackFilter(
                    authorizationCodeCallbackRequestMatcher, authenticationManager, authorizationRequestRepository,
                    relyingPartyRegistrationRepository, tokenEndpointClient, authorizationCodeSuccessRedirectUri);
            http.addFilterBefore(authorizationCodeCallbackFilter, UsernamePasswordAuthenticationFilter.class);
        }
    }

    public static <H extends HttpSecurityBuilder<H>> Oid4vpLoginConfigurer<H> oid4vpLogin() {
        return new Oid4vpLoginConfigurer<>();
    }
}
