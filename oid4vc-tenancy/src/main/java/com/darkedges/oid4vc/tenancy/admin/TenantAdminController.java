package com.darkedges.oid4vc.tenancy.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.function.Function;

/**
 * The admin API the AuthStack console calls with the signed-in person's console token ({@code Authorization: Bearer}):
 * <pre>
 * GET    /admin/api/tenants
 * GET    /admin/api/tenants/{environmentId}
 * PUT    /admin/api/tenants/{environmentId}                      {slug?, enabled?, settings?}
 * POST   /admin/api/tenants/{environmentId}/keys/{purpose}/rotate
 * DELETE /admin/api/tenants/{environmentId}/keys/{kid}            a retired key only
 * </pre>
 * The application's security configuration must let {@code /admin/api/**} through (no session, no CSRF): this controller checks the
 * token itself, with AuthStack.
 */
@RestController
@RequestMapping(path = "/admin/api/tenants", produces = MediaType.APPLICATION_JSON_VALUE)
public class TenantAdminController {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TenantAdministration administration;
    private final ConsoleAccounts accounts;

    public TenantAdminController(TenantAdministration administration, ConsoleAccounts accounts) {
        this.administration = administration;
        this.accounts = accounts;
    }

    @GetMapping
    public ResponseEntity<String> list(@RequestHeader(name = "Authorization", required = false) String authorization) {
        return as(authorization, administration::list);
    }

    @GetMapping("/{environmentId}")
    public ResponseEntity<String> get(@RequestHeader(name = "Authorization", required = false) String authorization,
                                      @PathVariable String environmentId) {
        return as(authorization, account -> administration.get(account, environmentId));
    }

    @PutMapping(path = "/{environmentId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> put(@RequestHeader(name = "Authorization", required = false) String authorization,
                                      @PathVariable String environmentId, @RequestBody String body) {
        JsonNode json;
        try {
            json = MAPPER.readTree(body);
        } catch (Exception e) {
            return respond(new TenantAdministration.Answer(400, MAPPER.createObjectNode()
                    .put("error", "invalid_request").put("error_description", "The body is not JSON")));
        }
        return as(authorization, account -> administration.put(account, environmentId, json));
    }

    @PostMapping("/{environmentId}/keys/{purpose}/rotate")
    public ResponseEntity<String> rotate(@RequestHeader(name = "Authorization", required = false) String authorization,
                                         @PathVariable String environmentId, @PathVariable String purpose) {
        return as(authorization, account -> administration.rotate(account, environmentId, purpose));
    }

    @DeleteMapping("/{environmentId}/keys/{kid}")
    public ResponseEntity<String> removeRetiredKey(@RequestHeader(name = "Authorization", required = false) String authorization,
                                                   @PathVariable String environmentId, @PathVariable String kid) {
        return as(authorization, account -> administration.removeRetiredKey(account, environmentId, kid));
    }

    private ResponseEntity<String> as(String authorization, Function<ConsoleAccount, TenantAdministration.Answer> action) {
        String token = authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)
                ? authorization.substring(7).trim() : null;
        ConsoleAccount account;
        try {
            account = accounts.verify(token);
        } catch (ConsoleAccounts.ConsoleAccountException e) {
            return respond(new TenantAdministration.Answer(e.status(), MAPPER.createObjectNode()
                    .put("error", e.status() == 401 ? "unauthorized" : e.status() == 403 ? "forbidden" : "temporarily_unavailable")
                    .put("error_description", e.getMessage())));
        }
        return respond(action.apply(account));
    }

    private static ResponseEntity<String> respond(TenantAdministration.Answer answer) {
        return ResponseEntity.status(answer.status()).contentType(MediaType.APPLICATION_JSON).body(answer.body().toString());
    }
}
