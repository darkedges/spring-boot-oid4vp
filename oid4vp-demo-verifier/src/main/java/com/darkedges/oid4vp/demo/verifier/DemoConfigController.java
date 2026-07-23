package com.darkedges.oid4vp.demo.verifier;

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
 */
@RestController
public class DemoConfigController {

    private final String walletBaseUrlForBrowser;
    private final String verifierBaseUrlForWallet;

    public DemoConfigController(
            @Value("${demo.wallet-base-url-for-browser}") String walletBaseUrlForBrowser,
            @Value("${demo.verifier-base-url-for-wallet}") String verifierBaseUrlForWallet) {
        this.walletBaseUrlForBrowser = walletBaseUrlForBrowser;
        this.verifierBaseUrlForWallet = verifierBaseUrlForWallet;
    }

    @GetMapping(value = "/demo-config", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> demoConfig() {
        return Map.of(
                "walletBaseUrl", walletBaseUrlForBrowser,
                "verifierAuthorizeUrlForWallet", verifierBaseUrlForWallet + "/oid4vp/authorize/demo");
    }
}
