#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
workdir="$root/build/got-opt-measure"
cc=${X86_64_CC:-x86_64-linux-gnu-gcc}
objdump=${X86_64_OBJDUMP:-x86_64-linux-gnu-objdump}
qemu_on=${QEMU_GOT_ON:-$root/build-got-on/qemu-x86_64}
qemu_off=${QEMU_GOT_OFF:-$root/build-got-off/qemu-x86_64}
iters=${GOT_MEASURE_ITERS:-10000}
do_build_qemu=0

usage() {
    cat <<EOF
Usage: $0 [--build-qemu] [--qemu-on PATH] [--qemu-off PATH] [--cc CC] [--iters N]

Builds a tiny x86_64 guest that executes RIP-relative GOT indirect call/jmp,
then compares CONFIG_INDIRECT_JUMP_OPT_GOT_DEBUG counters from two qemu-x86_64
binaries.

Environment:
  X86_64_CC         guest compiler, default: x86_64-linux-gnu-gcc
  X86_64_OBJDUMP    guest objdump, default: x86_64-linux-gnu-objdump
  QEMU_GOT_ON       optimized/debug qemu-x86_64 path
  QEMU_GOT_OFF      baseline qemu-x86_64 path
  QEMU_LD_PREFIX    optional x86_64 guest sysroot for dynamic loader/libs
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
    --build-qemu) do_build_qemu=1 ;;
    --qemu-on) qemu_on=$2; shift ;;
    --qemu-off) qemu_off=$2; shift ;;
    --cc) cc=$2; shift ;;
    --iters) iters=$2; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
done

need_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing tool: $1" >&2
        exit 1
    fi
}

configure_qemu() {
    build_dir=$1
    shift

    mkdir -p "$root/$build_dir"
    (
        cd "$root/$build_dir"
        "$root/configure" \
            --extra-cflags="-gdwarf-2 -g3 -O0" \
            --enable-linux-user \
            --target-list=x86_64-linux-user \
            --prefix=/usr \
            --sysconfdir=/etc \
            --libdir=/usr/lib/x86_64-linux-gnu \
            --libexecdir=/usr/lib/qemu \
            --interp-prefix=/home/dongwei/lib/qemu-binfmt/%M \
            --disable-docs \
            --disable-werror \
            --disable-blobs \
            --enable-debug \
            --enable-debug-stack-usage \
            --enable-debug-tcg \
            --enable-debug-info \
            --disable-reg-opt \
            --disable-inst-opt \
            --disable-func-opt \
            --enable-pbrp \
            --enable-pre-translate-log \
            "$@"
        make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" qemu-x86_64
    )
}

build_guest() {
    mkdir -p "$workdir"
    cat >"$workdir/libgot_target.c" <<'EOF'
#include <stdint.h>

volatile uint64_t got_sink;

__attribute__((noinline)) void got_target(void)
{
    got_sink++;
}
EOF

    cat >"$workdir/got_indirect_guest.c" <<'EOF'
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void got_target(void);

static __attribute__((noinline)) void got_call_once(void)
{
    __asm__ __volatile__("call *got_target@GOTPCREL(%%rip)" ::: "memory");
}

static __attribute__((noinline)) void got_jmp_once(void)
{
    __asm__ __volatile__(
        "lea 1f(%%rip), %%rax\n\t"
        "push %%rax\n\t"
        "jmp *got_target@GOTPCREL(%%rip)\n\t"
        "1:"
        :
        :
        : "rax", "memory");
}

int main(int argc, char **argv)
{
    long n = argc > 1 ? strtol(argv[1], 0, 0) : 10000;

    for (long i = 0; i < n; i++) {
        got_call_once();
        got_jmp_once();
    }
    puts("got-indirect-ok");
    return 0;
}
EOF

    "$cc" -shared -fPIC -O2 -o "$workdir/libgot_target.so" \
        "$workdir/libgot_target.c"
    "$cc" -O2 -fPIE -pie -Wa,-mrelax-relocations=no \
        -Wl,-rpath,'$ORIGIN' -L"$workdir" \
        -o "$workdir/got_indirect_guest" \
        "$workdir/got_indirect_guest.c" -lgot_target

    if command -v "$objdump" >/dev/null 2>&1; then
        "$objdump" -dr "$workdir/got_indirect_guest" >"$workdir/got_indirect_guest.objdump"
        if ! grep -Eq 'call[[:space:]]+\*.*\(%rip\)|jmp[[:space:]]+\*.*\(%rip\)' \
             "$workdir/got_indirect_guest.objdump"; then
            echo "guest does not contain RIP-relative indirect call/jmp; see $workdir/got_indirect_guest.objdump" >&2
            exit 1
        fi
    else
        echo "warning: $objdump not found; skipped instruction-shape check" >&2
    fi
}

run_one() {
    label=$1
    qemu=$2
    log=$workdir/$label.log

    if [ ! -x "$qemu" ]; then
        printf '%-8s qemu=missing path=%s\n' "$label" "$qemu"
        return
    fi

    set +e
    "$qemu" "$workdir/got_indirect_guest" "$iters" >"$log" 2>&1
    status=$?
    set -e

    printf '%-8s qemu=%s status=%s log=%s\n' "$label" "$qemu" "$status" "$log"
    awk '
      /got: indirect_call=/ {
        for (i = 2; i <= NF; i++) {
          split($i, a, "="); got[a[1]] = a[2]
        }
      }
      /got_runtime: guard_hits=/ {
        for (i = 2; i <= NF; i++) {
          split($i, a, "="); rt[a[1]] = a[2]
        }
      }
      END {
        if (!("indirect_call" in got)) {
          print "  counters: unavailable"
          exit
        }
        printf "  got: indirect_call=%s indirect_jmp=%s rip_call=%s rip_jmp=%s slot_readable=%s target_exec=%s target_changed=%s\n", got["indirect_call"], got["indirect_jmp"], got["rip_call"], got["rip_jmp"], got["slot_readable"], got["target_exec"], got["target_changed"]
        printf "  got_runtime: guard_hits=%s guard_misses=%s\n", rt["guard_hits"], rt["guard_misses"]
        printf "  hit_condition: rip_call>0 && rip_jmp>0 && slot_readable>0 && target_exec>0 && guard_hits>0 => %s\n", (got["rip_call"] > 0 && got["rip_jmp"] > 0 && got["slot_readable"] > 0 && got["target_exec"] > 0 && rt["guard_hits"] > 0 ? "yes" : "no")
      }
    ' "$log"
}

need_tool "$cc"

if [ "$do_build_qemu" -eq 1 ]; then
    configure_qemu build-got-on \
        --enable-indirect-jump-opt-got \
        --enable-indirect-jump-opt-got-debug
    configure_qemu build-got-off \
        --disable-indirect-jump-opt-got \
        --disable-indirect-jump-opt-got-debug
fi

build_guest
echo "guest=$workdir/got_indirect_guest"
echo "iters=$iters"
run_one "got-on" "$qemu_on"
run_one "got-off" "$qemu_off"
