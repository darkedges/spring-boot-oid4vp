#!/usr/bin/env bash
# Walks through the full OpenID4VP demo flow (Verifier issues a request -> Wallet builds and posts a
# presentation -> Verifier verifies it -> same-device redirect_uri handoff -> protected /profile access),
# pausing after each step so you can inspect what happened. See README.md for the manual (non-scripted)
# version of the same walkthrough.
#
# Usage:
#   ./demo.sh              # starts both apps with `docker compose up --build`, runs the walkthrough
#   ./demo.sh --no-docker  # assumes both apps are already running (see README: "Running the demo" step 1)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

VERIFIER_URL="http://localhost:8090"
WALLET_URL="http://localhost:8081"
USE_DOCKER=1

for arg in "$@"; do
  case "$arg" in
    --no-docker) USE_DOCKER=0 ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done

# Color only when writing to a real terminal and the user hasn't opted out (https://no-color.org).
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'
  RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'
  RESET=$'\033[0m'
  JQ_COLOR="-C"
else
  BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
  JQ_COLOR=""
fi

COOKIES="$(mktemp)"
cleanup() { rm -f "$COOKIES"; }
trap cleanup EXIT

step() {
  echo
  echo "${BOLD}${CYAN}════════════════════════════════════════════════════════════════════${RESET}"
  echo "${BOLD}${CYAN}  $1${RESET}"
  echo "${BOLD}${CYAN}════════════════════════════════════════════════════════════════════${RESET}"
}

pause() {
  echo
  read -rp "${DIM}Press Enter to continue... ${RESET}" _
}

cmd() {
  echo "${DIM}\$ $1${RESET}"
  echo
}

# Pretty-prints JSON from stdin, syntax-colored via jq if available, else plain.
print_json() {
  if command -v jq >/dev/null 2>&1; then
    jq $JQ_COLOR .
  elif command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool
  else
    cat
  fi
}

json_field() {
  python3 -c "import sys,json; print(json.load(sys.stdin)[\"$1\"])"
}

# Prints "HTTP <code>" in green for 2xx, red otherwise.
print_status() {
  local code="$1"
  local color="$RED"
  [[ "$code" == 2* ]] && color="$GREEN"
  echo "${color}${BOLD}HTTP $code${RESET}"
}

if [ "$USE_DOCKER" = "1" ]; then
  step "Starting demo apps (docker compose up --build)"
  docker compose up -d --build

  echo "${DIM}Waiting for the Wallet (localhost:8081) and Verifier (localhost:8090) to become ready...${RESET}"
  until curl -sf -o /dev/null "$WALLET_URL/issuer-jwks"; do sleep 1; done
  until curl -sf -o /dev/null "$VERIFIER_URL/oid4vp/authorize/demo"; do sleep 1; done
  echo "${GREEN}Both apps are up.${RESET}"
  WALLET_INTERNAL_VERIFIER_URL="http://verifier:8090"
else
  step "Assuming both apps are already running on localhost:8081 / localhost:8090 (--no-docker)"
  WALLET_INTERNAL_VERIFIER_URL="$VERIFIER_URL"
fi
pause

step "1. Verifier issues a fresh Authorization Request"
cmd "curl $VERIFIER_URL/oid4vp/authorize/demo"
REQUEST_JSON="$(curl -s "$VERIFIER_URL/oid4vp/authorize/demo")"
echo "$REQUEST_JSON" | print_json
pause

step "2. Wallet fetches that request, builds a presentation, and POSTs it to the Verifier"
cmd "curl -X POST $WALLET_URL/present -d '{\"verifierAuthorizeUrl\":\"$WALLET_INTERNAL_VERIFIER_URL/oid4vp/authorize/demo\"}'"
PRESENT_RESPONSE="$(curl -s -X POST "$WALLET_URL/present" \
  -H "Content-Type: application/json" \
  -d "{\"verifierAuthorizeUrl\":\"$WALLET_INTERNAL_VERIFIER_URL/oid4vp/authorize/demo\"}")"
echo "$PRESENT_RESPONSE" | print_json
REDIRECT_URI="$(echo "$PRESENT_RESPONSE" | json_field redirect_uri)"
echo
echo "${GREEN}The Verifier accepted the presentation${RESET} and returned a same-device redirect_uri:"
echo "  ${YELLOW}${REDIRECT_URI}${RESET}"
pause

step "3. Follow the redirect_uri (this is what the End-User's browser would do) — establishes a session"
cmd "curl -c cookies.txt \"$REDIRECT_URI\""
curl -s -c "$COOKIES" "$REDIRECT_URI" | print_json
pause

step "4. Access the protected /profile endpoint WITH the session cookie"
cmd "curl -b cookies.txt $VERIFIER_URL/profile"
curl -s -b "$COOKIES" "$VERIFIER_URL/profile" | print_json
pause

step "5. Access /profile WITHOUT the cookie — should be denied"
cmd "curl $VERIFIER_URL/profile"
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$VERIFIER_URL/profile")"
print_status "$CODE"
pause

step "Done."
if [ "$USE_DOCKER" = "1" ]; then
  read -rp "Stop the demo apps (docker compose down)? [Y/n] " ans
  if [[ "${ans:-Y}" != "n" && "${ans:-Y}" != "N" ]]; then
    docker compose down
  fi
fi
