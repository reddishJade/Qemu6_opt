#!/usr/bin/env bash
# Run standalone lifecycle guests; this script never invokes SPEC.
# Usage: bash run-rfich-lifecycle.sh OUTPUT MIXED_GUEST BASELINE RFICH PBRP DEBUG
set -euo pipefail
out=$1
mixed=$2
shift 2
variants=(baseline rfich pbrp debug)
binaries=("$@")
[[ ${#binaries[@]} == 4 ]] || exit 2
test_root=${RFICH_TEST_ROOT:-/home/dongwei/test}
mkdir -p "$out"
printf 'case,variant,run_rc,stdout_match\n' > "$out/summary.csv"
failed=0

run_case() {
    local name=$1
    shift
    local i rc match
    for i in "${!binaries[@]}"; do
        local prefix="$out/$name.${variants[i]}"
        rc=0
        timeout 60s "${binaries[i]}" "$@" >"$prefix.stdout" \
            2>"$prefix.stderr" || rc=$?
        match=0
        if [[ $rc == 0 ]] && cmp -s "$out/$name.baseline.stdout" \
                                      "$prefix.stdout"; then
            match=1
        else
            failed=1
        fi
        printf '%s,%s,%s,%s\n' "$name" "${variants[i]}" "$rc" "$match" \
            | tee -a "$out/summary.csv"
    done
}

run_case hello "$test_root/hello"
run_case mixed "$mixed"
run_case mixed_singlestep -singlestep "$mixed"
run_case mixed_nochain -d nochain "$mixed"
for mode in stable delayed swap top3 entropy; do
    run_case "$mode" "$test_root/indirect-jump/rfich_adaptive_micro.x86_64" \
        "$mode" 100000
done
run_case recursive "$test_root/indirect-jump/rfich_recursive_pbrp_stress.x86_64"
run_case retry "$test_root/indirect-jump/rfich_retry_stress.x86_64" 100000
run_case threads "$test_root/indirect-jump/rfich_mt_stress.x86_64" 8 200000
run_case smc_unlink "$test_root/indirect-jump/rfich_smc_unlink_race.x86_64" 8 20000
run_case smc_both "$test_root/indirect-jump/rfich_smc_both_mt_stress.x86_64" 8 20000

# A return-code-only pass could hide a completely inactive RFICH path.
if ! grep -Eq 'RFICH patch attempts=[0-9]+ successes=[1-9][0-9]*' \
        "$out/mixed.debug.stderr"; then
    echo 'FAIL: mixed guest did not patch any RFICH edge' >&2
    failed=1
fi
if ! grep -Eq 'resets=[1-9][0-9]*' "$out/mixed.debug.stderr"; then
    echo 'FAIL: mixed guest did not reset any RFICH edge' >&2
    failed=1
fi
for index in 0 1 2; do
    if ! grep -Eq "RFICH-DEBUG patch site=.* index=$index target=" \
            "$out/mixed.debug.stderr"; then
        echo "FAIL: mixed guest did not patch slot $index" >&2
        failed=1
    fi
done
exit "$failed"
