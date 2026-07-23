package com.darkedges.oid4vp.demo.verifier;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Tells the browser demo page ({@code static/index.html}) which URL to hand the Wallet for it to fetch
 * our Authorization Request from. Can't just use the page's own origin: under the docker-compose profile,
 * that's a {@code localhost} URL the browser can reach but the Wallet's own container cannot (its
 * {@code localhost} is itself) — see {@code application-docker.yml}.
 */
@RestController
public class DemoConfigController {

    private final String verifierBaseUrlForWallet;

    public DemoConfigController(@Value("${demo.verifier-base-url-for-wallet}") String verifierBaseUrlForWallet) {
        this.verifierBaseUrlForWallet = verifierBaseUrlForWallet;
    }

    @GetMapping(value = "/demo-config", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, String> demoConfig() {
        return Map.of("verifierAuthorizeUrlForWallet", verifierBaseUrlForWallet + "/oid4vp/authorize/demo");
    }
}
