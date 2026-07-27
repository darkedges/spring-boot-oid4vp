#!/usr/bin/env python3
"""Automates a single OpenID4VP Relying Party (Verifier) conformance run against a
self-hosted gitlab.com/openid/conformance-suite instance, replacing the manual workflow
documented in the top-level README.md ("Extra relying parties for conformance testing" /
"Invoking a Wallet").

What it does, end to end:
  1. Brings up the demo Verifier under the `cloudflare` docker compose profile (skip with
     --no-compose if it's already running; add --with-tunnel if your Cloudflare tunnel is
     also managed via docker-compose.tunnel.yml rather than some other long-lived setup).
  2. Creates a test plan on the conformance suite from a JSON config file (e.g.
     conformance/zkp-iso-mdl-test-config.json) and a variant, then instantiates and starts one
     of its test modules.
  3. Derives that module's mock-Wallet `authorization_endpoint` from its base URL.
  4. Restarts the Verifier container with that URL wired into the right registration's
     wallet-authorization-endpoint env var (this mirrors today's real deployment constraint:
     the value is read once at container startup, so a restart is unavoidable per run).
  5. Triggers the exchange headlessly by following redirects through
     https://<verifier-host>/oid4vp/invoke/<alias> -- a plain HTTP redirect chain to the
     suite's exposed endpoint and back to our response endpoint, no real browser/JS required.
  6. Polls the suite until the module finishes, prints a pass/fail summary, and exits 0 if
     every test in the module passed, 1 otherwise.

Environment variables:
  CONFORMANCE_SERVER        Base URL of your self-hosted conformance-suite instance, e.g.
                             https://conformance.example.internal/. Required.
  CONFORMANCE_TOKEN         Bearer API token, if your instance requires one. Omit for a
                             dev-mode instance with no auth.
  CONFORMANCE_INSECURE_TLS  Set to "1" to skip TLS verification against the suite (common for
                             self-hosted instances using a self-signed cert).

Usage:
  conformance/run_conformance.py \\
      --config conformance/zkp-iso-mdl-test-config.json \\
      --plan-name oid4vp-1final-verifier-test-plan \\
      --variant '{"credential_format":"iso_mdl","client_id_prefix":"x509_hash","request_method":"request_uri_signed","vp_profile":"haip","response_mode":"direct_post.jwt"}' \\
      --module oid4vp-1final-verifier-happy-flow \\
      --alias conformancemdoc

Creating a plan (POST /api/plan) only registers it and lists its constituent test module names
-- it does not itself instantiate a runnable module. A second call (POST /api/runner, i.e.
--module) actually creates and starts one, and its response's "url" field is the module's own
base URL; the mock-Wallet endpoint the Verifier should be pointed at is always "<url>/authorize"
(confirmed against a live instance: the suite exposes OIDC-style discovery under that base,
e.g. "<url>/authorize", "<url>/token", "<url>/jwks").
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

COMPOSE_FILES = [
    "docker-compose.yml",
    "docker-compose.cloudflare.yml",
]

# registration alias -> (env var carrying the exported authorization_endpoint,
#                         env var carrying the exported token_endpoint, or None)
# Mirrors README.md's "Invoking a Wallet" section exactly.
ALIAS_ENV = {
    "conformance": ("CONFORMANCE_WALLET_AUTHORIZATION_ENDPOINT", None),
    "conformancemdoc": ("CONFORMANCE_MDOC_WALLET_AUTHORIZATION_ENDPOINT", None),
    "conformancecode": (
        "CONFORMANCE_CODE_WALLET_AUTHORIZATION_ENDPOINT",
        "CONFORMANCE_CODE_WALLET_TOKEN_ENDPOINT",
    ),
}

DEFAULT_VERIFIER_HOST = "https://verify.irving.au"

TERMINAL_STATES = {"FINISHED", "INTERRUPTED"}


class ConformanceError(RuntimeError):
    pass


class ConformanceClient:
    """Thin wrapper over the conformance-suite's REST API, confirmed against a live self-hosted
    instance: POST /api/plan to register a plan (returns its id + the names of its constituent
    test modules, but does NOT instantiate any of them), POST /api/runner to actually create
    and start one specific module from that plan (returns its own id + base url -- for an RP
    test like ours this module comes up already WAITING, no separate start call needed), GET
    /api/runner/{moduleId}/wait-state to block until a module reaches one of a set of states,
    GET /api/log/{moduleId} for its result log.
    """

    def __init__(self, base_url: str, token: str | None = None, insecure: bool = False):
        self.base_url = base_url.rstrip("/") + "/"
        self.token = token
        self.ssl_context = ssl._create_unverified_context() if insecure else None

    def _request(self, method: str, path: str, params: dict | None = None, json_body=None):
        url = self.base_url + path.lstrip("/")
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(json_body).encode("utf-8") if json_body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, context=self.ssl_context, timeout=35) as resp:
                body = resp.read()
                return resp.status, (json.loads(body) if body else None)
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                parsed = json.loads(body) if body else None
            except json.JSONDecodeError:
                parsed = body.decode("utf-8", "replace")
            return e.code, parsed

    def create_test_plan(self, plan_name: str, config: dict, variant: dict | None = None) -> dict:
        params = {"planName": plan_name}
        if variant:
            params["variant"] = json.dumps(variant)
        status, body = self._request("POST", "api/plan", params=params, json_body=config)
        if status != 201:
            raise ConformanceError(f"create_test_plan failed: HTTP {status}: {body}")
        return body

    def create_test_module(self, plan_id: str, test_module: str, variant: dict | None = None) -> dict:
        """Instantiates and starts one specific module of an already-created plan. Returns
        {"name": <testModule>, "id": <moduleId>, "url": <moduleBaseUrl>}."""
        params = {"test": test_module, "plan": plan_id}
        if variant:
            params["variant"] = json.dumps(variant)
        status, body = self._request("POST", "api/runner", params=params)
        if status != 201:
            raise ConformanceError(f"create_test_module failed: HTTP {status}: {body}")
        return body

    def wait_for_state(self, module_id: str, states: list[str], timeout_ms: int = 30000) -> dict:
        """Blocks (server-side, up to timeout_ms) until the module reaches one of `states`.
        On success returns the module's info dict (same shape as a state snapshot, with a
        "status" key); on a client-side timeout, confirmed live, the body is just
        {"timeout": true} -- no "status" key at all, since the module simply hasn't reached
        any of the requested states yet. Callers must treat that as "still waiting", not as a
        state transition."""
        status, body = self._request(
            "GET",
            f"api/runner/{module_id}/wait-state",
            params={"states": ",".join(states), "timeoutMs": timeout_ms},
        )
        if status != 200:
            raise ConformanceError(f"wait_for_state failed: HTTP {status}: {body}")
        return body

    def test_log(self, module_id: str) -> list:
        status, body = self._request("GET", f"api/log/{module_id}")
        if status != 200:
            raise ConformanceError(f"test_log failed: HTTP {status}: {body}")
        return body


def sh(cmd: list[str], **kwargs):
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.run(cmd, cwd=REPO_ROOT, check=True, **kwargs)


def compose_cmd(*extra: str, with_tunnel: bool = False) -> list[str]:
    cmd = ["docker", "compose"]
    files = COMPOSE_FILES + (["docker-compose.tunnel.yml"] if with_tunnel else [])
    for f in files:
        cmd += ["-f", f]
    cmd += list(extra)
    return cmd


def bring_up_stack(env_overrides: dict[str, str], with_tunnel: bool = False):
    env = os.environ.copy()
    env.update(env_overrides)
    sh(compose_cmd("up", "-d", "--build", with_tunnel=with_tunnel), env=env)
    wait_for_verifier_ready()


def wait_for_verifier_ready(timeout_s: int = 60):
    """A freshly (re)started container is marked "Started" by docker compose well before the
    Spring Boot app inside it has finished starting up -- confirmed live: firing the invoke
    request immediately after `compose up` returned a 403 (still on the old/half-up process)
    even though the exact same request succeeded moments later. Poll the same readiness check
    demo.sh uses before doing anything that depends on the app actually being up."""
    deadline = time.monotonic() + timeout_s
    url = "http://localhost:8090/oid4vp/authorize/demo"
    print(f"Waiting for the Verifier to become ready ({url}) ...", file=sys.stderr)
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                if resp.status == 200:
                    return
        except (OSError, TimeoutError):
            # Covers connection-refused (app not listening yet) as well as connection-reset
            # (container mid-restart, old process's socket torn down under us) -- both mean
            # "not ready yet, keep polling", confirmed live during a real container restart.
            pass
        time.sleep(1)
    raise ConformanceError(f"Verifier did not become ready at {url} within {timeout_s}s")


def authorization_endpoint_for(module_url: str) -> str:
    """The suite exposes an OIDC-style discovery surface under each running module's base url
    (confirmed against a live instance): "<url>/authorize", "<url>/token", "<url>/jwks", etc.
    The mock-Wallet endpoint a Verifier under test should be pointed at is "<url>/authorize"."""
    return module_url.rstrip("/") + "/authorize"


def trigger_exchange(invoke_url: str) -> tuple[int, str]:
    """Follows redirects through GET <verifier>/oid4vp/invoke/<alias> the way a browser would.
    This is a plain HTTP redirect chain (the suite's endpoint does the actual presentation
    work server-side), so no JS execution is required -- a cookie-aware urllib opener is
    enough to complete it."""
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    req = urllib.request.Request(invoke_url, method="GET")
    try:
        with opener.open(req, timeout=35) as resp:
            return resp.status, resp.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.geturl()


def summarize_log(log: list) -> tuple[int, int, int, list[str]]:
    """Returns (passed, warning, failed, failure_messages) from a suite test-log array."""
    counts = {"SUCCESS": 0, "WARNING": 0, "FAILURE": 0}
    failures = []
    for entry in log:
        result = entry.get("result")
        if result in counts:
            counts[result] += 1
        if result == "FAILURE":
            failures.append(entry.get("msg", str(entry)))
    return counts["SUCCESS"], counts["WARNING"], counts["FAILURE"], failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True, help="Path to a conformance-suite test-plan JSON config, e.g. conformance/zkp-iso-mdl-test-config.json")
    parser.add_argument("--plan-name", required=True, help="Test plan name, as shown in the suite's plan catalogue")
    parser.add_argument("--variant", default=None, help="JSON object for the plan variant, if the plan needs one")
    parser.add_argument("--alias", required=True, choices=sorted(ALIAS_ENV), help="Which demo-verifier registration to drive")
    parser.add_argument("--verifier-host", default=DEFAULT_VERIFIER_HOST, help=f"Base URL of the tunnelled Verifier (default: {DEFAULT_VERIFIER_HOST})")
    parser.add_argument("--module", default=None, help="testModule name to run from the plan, e.g. oid4vp-1final-verifier-happy-flow (default: the plan's first module)")
    parser.add_argument("--no-compose", action="store_true", help="Assume the Verifier is already running under the cloudflare profile; don't bring it up or restart it")
    parser.add_argument("--with-tunnel", action="store_true", help="Also layer on docker-compose.tunnel.yml (needs CLOUDFLARE_TUNNEL_TOKEN). Omit if your tunnel is managed some other way (e.g. a separate long-lived cloudflared deployment)")
    parser.add_argument("--wait-timeout-s", type=int, default=180, help="Max seconds to wait for the test module to finish")
    args = parser.parse_args()

    server = os.environ.get("CONFORMANCE_SERVER")
    if not server:
        print("CONFORMANCE_SERVER must be set to your self-hosted conformance-suite base URL", file=sys.stderr)
        return 2
    token = os.environ.get("CONFORMANCE_TOKEN")
    insecure = os.environ.get("CONFORMANCE_INSECURE_TLS") == "1"

    with open(args.config, "r", encoding="utf-8") as f:
        config = json.load(f)
    variant = json.loads(args.variant) if args.variant else None

    client = ConformanceClient(server, token=token, insecure=insecure)

    print(f"Creating test plan {args.plan_name!r} on {server} ...", file=sys.stderr)
    plan = client.create_test_plan(args.plan_name, config, variant)
    plan_id = plan["id"]
    modules = plan.get("modules", [])
    if not modules:
        raise ConformanceError(f"Created plan {plan_id} has no modules in the response: {plan}")

    if args.module:
        matching = [m for m in modules if m.get("testModule") == args.module]
        if not matching:
            available = ", ".join(m.get("testModule", "?") for m in modules)
            raise ConformanceError(f"--module {args.module!r} is not in this plan's modules: {available}")
        test_module = args.module
    else:
        test_module = modules[0]["testModule"]

    print(f"Plan {plan_id} created with {len(modules)} module(s); starting {test_module!r}", file=sys.stderr)
    created = client.create_test_module(plan_id, test_module, variant)
    module_id = created["id"]
    module_url = created["url"]
    print(f"Module {module_id} started at {module_url}", file=sys.stderr)

    info = client.wait_for_state(module_id, ["WAITING"], timeout_ms=30000)

    auth_endpoint = authorization_endpoint_for(module_url)
    print(f"Mock-Wallet authorization_endpoint: {auth_endpoint}", file=sys.stderr)

    env_var, _token_env_var = ALIAS_ENV[args.alias]
    if not args.no_compose:
        bring_up_stack({env_var: auth_endpoint}, with_tunnel=args.with_tunnel)
    else:
        print(
            f"--no-compose set: make sure the running stack already has {env_var}={auth_endpoint}",
            file=sys.stderr,
        )

    invoke_url = f"{args.verifier_host.rstrip('/')}/oid4vp/invoke/{args.alias}"
    print(f"Triggering exchange: GET {invoke_url}", file=sys.stderr)
    status, final_url = trigger_exchange(invoke_url)
    print(f"Redirect chain ended at HTTP {status}: {final_url}", file=sys.stderr)

    deadline = time.monotonic() + args.wait_timeout_s
    state = info.get("status")
    while state not in TERMINAL_STATES and time.monotonic() < deadline:
        remaining_ms = max(1000, int((deadline - time.monotonic()) * 1000))
        response = client.wait_for_state(module_id, list(TERMINAL_STATES), timeout_ms=min(30000, remaining_ms))
        if response.get("timeout"):
            continue  # still not in a terminal state -- keep polling, don't overwrite `info`/`state`
        info = response
        state = info.get("status")

    if state not in TERMINAL_STATES:
        print(f"Module {module_id} did not finish within {args.wait_timeout_s}s (last known state: {state})", file=sys.stderr)
        return 1

    log = client.test_log(module_id)
    passed, warned, failed, failures = summarize_log(log)
    result = info.get("result", "UNKNOWN")
    print(f"\nModule {module_id} finished: status={state} result={result}")
    print(f"  {passed} passed, {warned} warnings, {failed} failed")
    for msg in failures:
        print(f"  FAILURE: {msg}")

    return 0 if state == "FINISHED" and failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ConformanceError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"error: command failed with exit code {e.returncode}", file=sys.stderr)
        sys.exit(1)
