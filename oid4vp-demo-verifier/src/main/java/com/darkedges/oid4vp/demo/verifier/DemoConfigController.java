package com.darkedges.oid4vp.demo.verifier;

import org.springframework.beans.factory.ObjectProvider;
import jakarta.servlet.http.HttpServletRequest;
import com.darkedges.oid4vp.spring.boot.autoconfigure.tenancy.Oid4vpTenancy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Tells the browser demo page ({@code static/index.html}) which URLs to use for the Wallet, rather than
 * having it hardcode its own origin / a fixed {@code localhost} Wallet URL — neither holds once the two
 * apps are deployed on separate domains (see {@code application-cloudflare.yml}) or run under
 * docker-compose, where the Wallet's own container can't reach us via {@code localhost} (that's itself).
 * Also carries the display name shown in the page's copy, so rebranding the demo doesn't require
 * editing HTML.
 */
@RestController
public class DemoConfigController {

    private final String walletBaseUrlForBrowser;
    private final String verifierBaseUrlForWallet;
    private final String employerName;
    private final Oid4vpTenancy tenancy;

    public DemoConfigController(
            @Value("${demo.wallet-base-url-for-browser}") String walletBaseUrlForBrowser,
            @Value("${demo.verifier-base-url-for-wallet}") String verifierBaseUrlForWallet,
            @Value("${demo.employer-name}") String employerName,
            ObjectProvider<Oid4vpTenancy> tenancy) {
        this.tenancy = tenancy.getIfAvailable();
        this.walletBaseUrlForBrowser = walletBaseUrlForBrowser;
        this.verifierBaseUrlForWallet = verifierBaseUrlForWallet;
        this.employerName = employerName;
    }

    @GetMapping(value = "/demo-config", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> demoConfig(HttpServletRequest request) {
        // A tenant's own authorize URL; the deployment's for the default tenant.
        String defaultAuthorize = verifierBaseUrlForWallet + "/oid4vp/authorize/demo";
        String authorize = tenancy == null ? defaultAuthorize : tenancy.url("/oid4vp/authorize/demo", defaultAuthorize).apply(request);
        return Map.of(
                "walletBaseUrl", walletBaseUrlForBrowser,
                "verifierAuthorizeUrlForWallet", authorize,
                "employerName", employerName);
    }
}
