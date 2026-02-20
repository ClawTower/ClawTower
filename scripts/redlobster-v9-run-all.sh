#!/usr/bin/env bash
# Red Lobster v9 — Smorgasbord + New Attack Surfaces
# Threat model: compromised openclaw agent, NO sudo, NO clawsudo
# Usage: bash scripts/redlobster-v9-run-all.sh [flag18|flag19|flag20|flag21|flag22|flag23|all]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/redlobster-lib.sh" 2>/dev/null || true

RESULTS_DIR="/tmp/redlobster/results"
mkdir -p "$RESULTS_DIR"

FLAGS=(
    "flag18:redlobster-v9-flag18-greatest.sh:GREATEST HITS (regression smorgasbord)"
    "flag19:redlobster-v9-flag19-envpoison.sh:ENV POISONING"
    "flag20:redlobster-v9-flag20-timing.sh:TIMING & RACE CONDITIONS"
    "flag21:redlobster-v9-flag21-covert.sh:COVERT CHANNELS"
    "flag22:redlobster-v9-flag22-supply.sh:SUPPLY CHAIN"
    "flag23:redlobster-v9-flag23-selftarget.sh:SELF-TARGETING"
)

TARGET="${1:-all}"

CT_VERSION="$(cat "$SCRIPT_DIR/../VERSION" 2>/dev/null || echo 'unknown')"
echo "┌───────────────────────────────────────────────────────┐"
echo "│  🦞 Red Lobster v9 — Smorgasbord + New Surfaces        │"
echo "│  ClawTower $CT_VERSION                                       │"
echo "│  $(date '+%Y-%m-%d %H:%M:%S %Z')                              │"
echo "│  Target: $TARGET                                             │"
echo "│  User: $(whoami) (uid=$(id -u))                              │"
echo "│  Threat model: NO sudo, NO clawsudo                         │"
echo "└───────────────────────────────────────────────────────┘"
echo ""

# Verify we are NOT root
if [[ "$(id -u)" == "0" ]]; then
    echo "❌ v9 must run as non-root user (agent threat model). Aborting."
    exit 1
fi

PASS=0
FAIL=0
SKIP=0

for entry in "${FLAGS[@]}"; do
    IFS=: read -r key script label <<< "$entry"
    if [[ "$TARGET" != "all" && "$TARGET" != "$key" ]]; then continue; fi

    echo "═══ [$key] $label ═══"
    if [[ -f "$SCRIPT_DIR/$script" ]]; then
        if bash "$SCRIPT_DIR/$script"; then
            echo "  ✅ $label — PASS"
            ((PASS++))
        else
            echo "  ❌ $label — FAIL (exit $?)"
            ((FAIL++))
        fi
    else
        echo "  ⏭️  $label — SKIP (script not found)"
        ((SKIP++))
    fi
    echo ""
done

echo "┌─── v9 Scorecard ───┐"
echo "│ PASS: $PASS  FAIL: $FAIL  SKIP: $SKIP │"
echo "└────────────────────┘"

if [[ "$TARGET" == "all" ]]; then
    COMBINED="$RESULTS_DIR/v9-combined.md"
    {
        echo "# Red Lobster v9 — Smorgasbord + New Surfaces Results"
        echo ""
        echo "- **Date:** $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "- **ClawTower:** $CT_VERSION"
        echo "- **User:** $(whoami) (uid=$(id -u))"
        echo "- **Threat model:** Compromised agent, NO sudo, NO clawsudo"
        echo ""
        for entry in "${FLAGS[@]}"; do
            IFS=: read -r key script label <<< "$entry"
            result_file="$RESULTS_DIR/${key}.md"
            echo "---"
            echo "## $label ($key)"
            echo ""
            if [[ -f "$result_file" ]]; then
                cat "$result_file"
            else
                echo "_No result file found._"
            fi
            echo ""
        done
    } > "$COMBINED"
    echo "Combined report: $COMBINED"
fi

exit $FAIL
