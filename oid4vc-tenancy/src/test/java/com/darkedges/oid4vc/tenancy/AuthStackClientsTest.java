package com.darkedges.oid4vc.tenancy;

import com.darkedges.oid4vc.tenancy.admin.AuthStackConsoleAccounts;
import com.darkedges.oid4vc.tenancy.admin.ConsoleAccount;
import com.darkedges.oid4vc.tenancy.admin.ConsoleAccounts.ConsoleAccountException;
import com.darkedges.oid4vc.tenancy.domains.AuthStackDomainDirectory;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The two AuthStack calls, against a stand-in AuthStack. */
class AuthStackClientsTest {

    private HttpServer server;
    private URI base;
    private final AtomicReference<String> domains = new AtomicReference<>("[]");
    private final AtomicInteger domainCalls = new AtomicInteger();
    private final AtomicReference<String> seenDomainsAuthorization = new AtomicReference<>();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/auth/me", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            String body;
            int status = 200;
            switch (auth == null ? "" : auth) {
                case "Bearer org-admin" -> body = """
                        {"user":{"id":"u1","email":"a@bank.example","role":"ORG_ADMIN","organizationId":"org-1"},
                         "environments":[{"id":"env-bank","name":"Risk E Bank"}]}""";
                case "Bearer plain-user" -> body = "{\"user\":{\"id\":\"u9\",\"role\":\"USER\"}}";
                default -> { status = 401; body = "{}"; }
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.createContext("/as/token", exchange -> {
            byte[] bytes = "{\"access_token\":\"platform-token\",\"expires_in\":3600}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.createContext("/api/platform/domains", exchange -> {
            domainCalls.incrementAndGet();
            seenDomainsAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            assertThat(exchange.getRequestURI().getQuery()).isEqualTo("purpose=issuer");
            byte[] bytes = domains.get().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        base = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void consoleTokensAreBelievedOnlyAsAuthStackDescribesThem() {
        var accounts = new AuthStackConsoleAccounts(base, HttpClient.newHttpClient(), Clock.systemUTC());
        ConsoleAccount account = accounts.verify("org-admin");
        assertThat(account.role()).isEqualTo(ConsoleAccount.Role.ORG_ADMIN);
        assertThat(account.organizationId()).isEqualTo("org-1");
        assertThat(account.environments()).containsEntry("env-bank", "Risk E Bank");

        assertThatThrownBy(() -> accounts.verify("expired")).isInstanceOf(ConsoleAccountException.class)
                .extracting(e -> ((ConsoleAccountException) e).status()).isEqualTo(401);
        assertThatThrownBy(() -> accounts.verify("plain-user")).isInstanceOf(ConsoleAccountException.class)
                .extracting(e -> ((ConsoleAccountException) e).status()).isEqualTo(403);
        assertThatThrownBy(() -> accounts.verify(null)).isInstanceOf(ConsoleAccountException.class);
    }

    @Test
    void customDomainsComeFromAuthStackWithThePlatformWorkersToken() {
        domains.set("[{\"host\":\"Issuer.Bank.Example\",\"environmentId\":\"env-bank\",\"organizationId\":\"org-1\"}]");
        var directory = new AuthStackDomainDirectory(base, "issuer", base.resolve("/as/token"), "platform-worker", "secret",
                Duration.ofMinutes(5), Duration.ofSeconds(0), HttpClient.newHttpClient(), Clock.systemUTC());

        assertThat(directory.lookup("issuer.bank.example")).get().extracting(b -> b.environmentId()).isEqualTo("env-bank");
        assertThat(seenDomainsAuthorization.get()).isEqualTo("Bearer platform-token");

        // A domain that has just gone live is found by an early refresh.
        domains.set("[{\"host\":\"issuer.bank.example\",\"environmentId\":\"env-bank\"},{\"host\":\"vc.shop.example\",\"environmentId\":\"env-shop\"}]");
        assertThat(directory.lookup("vc.shop.example")).isPresent();
        int calls = domainCalls.get();

        // A known host is served from the cache.
        directory.lookup("issuer.bank.example");
        assertThat(domainCalls.get()).isEqualTo(calls);
    }

    @Test
    void unknownHostsDoNotFloodAuthStack() {
        var directory = new AuthStackDomainDirectory(base, "issuer", base.resolve("/as/token"), "platform-worker", "secret",
                Duration.ofMinutes(5), Duration.ofMinutes(1), HttpClient.newHttpClient(), Clock.systemUTC());
        for (int i = 0; i < 20; i++) directory.lookup("nobody-" + i + ".example");
        assertThat(domainCalls.get()).isLessThanOrEqualTo(2);
    }

    @Test
    void anUnreachableAuthStackKeepsTheDomainsAlreadyKnown() {
        domains.set("[{\"host\":\"issuer.bank.example\",\"environmentId\":\"env-bank\"}]");
        var directory = new AuthStackDomainDirectory(base, "issuer", base.resolve("/as/token"), "platform-worker", "secret",
                Duration.ofMillis(1), Duration.ofSeconds(0), HttpClient.newHttpClient(), Clock.systemUTC());
        assertThat(directory.lookup("issuer.bank.example")).isPresent();
        server.stop(0);
        assertThat(directory.lookup("issuer.bank.example")).isPresent();
    }
}
