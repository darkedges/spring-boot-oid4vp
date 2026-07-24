#!/usr/bin/env python3
"""Automates a single OpenID4VP Relying Party (Verifier) conformance run against a
self-hosted gitlab.com/openid/conformance-suite instance, replacing the manual workflow
documented in the top-level README.md ("Extra relying parties for conformance testing" /
"Invoking a Wallet").

What it does, end to end:
  1. Brings up the demo Verifier under the `cloudflare` + `tunnel` docker compose profiles
     (skip with --no-compose if it's already running).
  2. Creates and starts a test plan on the conformance suite from a JSON config file (e.g.
     conformance/zkp-iso-mdl-test-config.json).
  3. Waits for the resulting test module to expose its mock-Wallet `authorization_endpoint`.
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
      --plan-name oid4vp-1final-verifier-happy-path \\
      --alias conformancemdoc

Known unknowns (see conformance/README.md): the exact JSON shape the suite uses to expose a
module's "Exported Values" (in particular, where the mock-Wallet authorization_endpoint lives
in GET /api/info/{moduleId}'s response) is not pinned down from documentation alone -- it's
read via --export-path, which defaults to a best guess and prints the full module-info JSON to
help you find the right path on first run against your own instance.
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
    "docker-compose.tunnel.yml",
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
    """Thin wrapper over the conformance-suite's REST API, mirroring the request shapes used
    by the suite's own reference automation (gitlab.com/openid/conformance-suite's
    scripts/conformance.py + scripts/run-test-plan.py): POST /api/plan to create a plan,
    POST /api/runner/{moduleId} to start a module, GET /api/runner/{moduleId}/wait-state to
    block until a module reaches one of a set of states, GET /api/info/{moduleId} for a
    module's current state/config, GET /api/log/{moduleId} for its result log.
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

    def module_info(self, module_id: str) -> dict:
        status, body = self._request("GET", f"api/info/{module_id}")
        if status != 200:
            raise ConformanceError(f"module_info failed: HTTP {status}: {body}")
        return body

    def start_module(self, module_id: str) -> dict:
        status, body = self._request("POST", f"api/runner/{module_id}")
        if status != 200:
            raise ConformanceError(f"start_module failed: HTTP {status}: {body}")
        return body

    def wait_for_state(self, module_id: str, states: list[str], timeout_ms: int = 30000) -> dict:
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


def compose_cmd(*extra: str) -> list[str]:
    cmd = ["docker", "compose"]
    for f in COMPOSE_FILES:
        cmd += ["-f", f]
    cmd += list(extra)
    return cmd


def bring_up_stack(env_overrides: dict[str, str]):
    env = os.environ.copy()
    env.update(env_overrides)
    sh(compose_cmd("up", "-d", "--build"), env=env)


def extract_authorization_endpoint(module_info: dict, export_path: str) -> str:
    """Walks module_info via a dot-separated path (e.g. "exposed.authorization_endpoint").
    Prints the full module_info JSON and raises if the path doesn't resolve to a string, since
    the suite's exact export-field naming isn't pinned down from documentation alone -- see
    conformance/README.md."""
    node = module_info
    for key in export_path.split("."):
        if not isinstance(node, dict) or key not in node:
            print(json.dumps(module_info, indent=2), file=sys.stderr)
            raise ConformanceError(
                f"--export-path {export_path!r} did not resolve (stopped at {key!r}); "
                "see the module-info JSON above and re-run with the correct --export-path "
                "for your instance/plan."
            )
        node = node[key]
    if not isinstance(node, str):
        print(json.dumps(module_info, indent=2), file=sys.stderr)
        raise ConformanceError(
            f"--export-path {export_path!r} resolved to a non-string value: {node!r}"
        )
    return node


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
    parser.add_argument("--module-index", type=int, default=0, help="Which module in the created plan to run, if it contains more than one")
    parser.add_argument("--export-path", default="exposed.authorization_endpoint", help="Dot-path into the module-info JSON where the mock-Wallet authorization_endpoint lives (see conformance/README.md)")
    parser.add_argument("--no-compose", action="store_true", help="Assume the Verifier is already running under the cloudflare+tunnel profile")
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
    module_id = modules[args.module_index]["id"]
    print(f"Plan {plan_id} created, running module {module_id}", file=sys.stderr)

    info = client.module_info(module_id)
    if info.get("status") not in ("WAITING", "RUNNING"):
        client.start_module(module_id)
    info = client.wait_for_state(module_id, ["WAITING"], timeout_ms=30000)

    auth_endpoint = extract_authorization_endpoint(info, args.export_path)
    print(f"Exported authorization_endpoint: {auth_endpoint}", file=sys.stderr)

    env_var, _token_env_var = ALIAS_ENV[args.alias]
    if not args.no_compose:
        bring_up_stack({env_var: auth_endpoint})
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
        info = client.wait_for_state(module_id, list(TERMINAL_STATES), timeout_ms=min(30000, remaining_ms))
        state = info.get("status")

    if state not in TERMINAL_STATES:
        print(f"Module {module_id} did not finish within {args.wait_timeout_s}s (last state: {state})", file=sys.stderr)
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
