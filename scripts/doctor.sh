#!/bin/sh
# Validates the local toolchain against what `cargo xtask build` actually
# needs: nightly + rust-src for -Z build-std, bpf-linker, and an LLVM whose
# clang can target BPF. Install instructions live in CONTRIBUTING.md.
#
# Reports every problem it finds (no early exit) and exits nonzero if any
# check failed, so it can gate CI or a pre-build hook.
set -u

status=0
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; status=1; }
note() { printf '  \033[33mnote\033[0m  %s\n' "$*"; }

platform=$(uname -s)
printf 'monad-firewall doctor (%s)\n' "$platform"

if command -v rustup >/dev/null 2>&1; then
    ok "$(rustup --version 2>/dev/null | head -n1)"
else
    fail "rustup not found: install from https://rustup.rs"
fi

if command -v cargo >/dev/null 2>&1; then
    ok "$(cargo --version)"
else
    fail "cargo not found: install via rustup"
fi

if rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    ok "nightly toolchain (xtask builds eBPF with cargo +nightly)"
else
    fail "nightly toolchain missing: rustup toolchain install nightly"
fi

if rustup component list --toolchain nightly 2>/dev/null | grep -q '^rust-src.*(installed)'; then
    ok "rust-src on nightly (required by -Z build-std=core)"
else
    fail "rust-src missing: rustup component add rust-src --toolchain nightly"
fi

# Mirror xtask's own lookup: PATH first, then ~/.cargo/bin.
if command -v bpf-linker >/dev/null 2>&1; then
    ok "$(bpf-linker --version)"
elif [ -x "$HOME/.cargo/bin/bpf-linker" ]; then
    ok "$("$HOME/.cargo/bin/bpf-linker" --version) (in ~/.cargo/bin, not on PATH)"
else
    fail "bpf-linker not found: see CONTRIBUTING.md, Install BPF Linker"
fi

case "$platform" in
Darwin)
    if LLVM_PREFIX=$(brew --prefix llvm 2>/dev/null) && [ -x "$LLVM_PREFIX/bin/llvm-config" ]; then
        ok "Homebrew LLVM $("$LLVM_PREFIX/bin/llvm-config" --version) at $LLVM_PREFIX"
        if "$LLVM_PREFIX/bin/clang" --print-targets 2>/dev/null | grep -qw bpf; then
            ok "clang can target BPF"
        else
            fail "Homebrew clang lacks the bpf target (Apple's stub never has it): brew reinstall llvm"
        fi
    else
        fail "Homebrew LLVM missing: brew bundle"
    fi
    note "macOS cross-compiles and type-checks only; running the firewall needs a Linux guest (see CONTRIBUTING.md)"
    ;;
Linux)
    # Package names diverge enough that a single hint string is wrong almost
    # everywhere: bpftool ships as `bpf` on Arch but `bpftool` on Fedora and
    # `linux-tools-*` on older Ubuntu LTS, and only Debian names the headers
    # package after the running kernel. Resolve the package manager once, then
    # let each check ask for the dependency it actually wants.
    #
    # LFS is checked first and by identity rather than by tooling: it has no
    # package manager to probe for, so the usual `command -v` inference would
    # silently misfile it as `unknown`.
    if [ -e /etc/lfs-release ] || grep -qi 'linux from scratch' /etc/os-release 2>/dev/null; then
        distro=lfs
    elif command -v pacman >/dev/null 2>&1; then
        distro=arch
    elif command -v dnf >/dev/null 2>&1; then
        distro=fedora
    elif command -v apt-get >/dev/null 2>&1; then
        distro=debian
    else
        distro=unknown
    fi

    # Prints the command to fix one logical dependency. The unknown-distro
    # arms stay useful by naming the candidates rather than punting entirely.
    install_hint() {
        case "$distro:$1" in
        arch:llvm)     echo 'sudo pacman -S clang llvm' ;;
        arch:bpftool)  echo 'sudo pacman -S bpf' ;;
        arch:libelf)   echo 'sudo pacman -S libelf' ;;
        # Arch splits headers per kernel flavor, and the flavor is the suffix
        # of `uname -r` (no suffix at all for the stock `linux` package).
        arch:kheaders)
            case "$(uname -r)" in
            *-lts)      echo 'sudo pacman -S linux-lts-headers' ;;
            *-zen)      echo 'sudo pacman -S linux-zen-headers' ;;
            *-hardened) echo 'sudo pacman -S linux-hardened-headers' ;;
            *)          echo 'sudo pacman -S linux-headers' ;;
            esac
            ;;
        fedora:llvm)     echo 'sudo dnf install clang llvm' ;;
        fedora:bpftool)  echo 'sudo dnf install bpftool' ;;
        fedora:libelf)   echo 'sudo dnf install elfutils-libelf-devel' ;;
        fedora:kheaders) echo 'sudo dnf install kernel-devel' ;;
        debian:llvm)     echo 'sudo apt install clang llvm' ;;
        debian:bpftool)  echo "sudo apt install bpftool (or linux-tools-common linux-tools-$(uname -r) on older LTS)" ;;
        debian:libelf)   echo 'sudo apt install libelf-dev' ;;
        debian:kheaders) echo "sudo apt install linux-headers-$(uname -r)" ;;
        # LFS has nothing to invoke, so these name the artifact to build
        # rather than pretending there's a one-liner.
        lfs:llvm)     echo 'build LLVM+Clang (BLFS), with BPF in LLVM_TARGETS_TO_BUILD' ;;
        lfs:bpftool)  echo 'make -C <kernel-source>/tools/bpf/bpftool install' ;;
        lfs:libelf)   echo 'build elfutils (BLFS)' ;;
        lfs:kheaders) echo "point /lib/modules/$(uname -r)/build at the kernel tree you built" ;;
        *:llvm)     echo 'install clang + llvm; see CONTRIBUTING.md' ;;
        *:bpftool)  echo 'install bpftool (bpf on Arch, bpftool on Fedora/Debian, linux-tools-* on older Ubuntu LTS)' ;;
        *:libelf)   echo 'install libelf headers (libelf on Arch, elfutils-libelf-devel on Fedora, libelf-dev on Debian)' ;;
        *:kheaders) echo "install kernel headers (linux-headers on Arch, kernel-devel on Fedora, linux-headers-$(uname -r) on Debian)" ;;
        esac
    }

    if command -v clang >/dev/null 2>&1 && clang --print-targets 2>/dev/null | grep -qw bpf; then
        ok "$(clang --version | head -n1) with bpf target"
    else
        fail "clang with BPF support missing: $(install_hint llvm)"
    fi
    if command -v bpftool >/dev/null 2>&1; then
        ok "bpftool"
    else
        fail "bpftool missing: $(install_hint bpftool)"
    fi
    if ldconfig -p 2>/dev/null | grep -q libelf; then
        ok "libelf"
    else
        fail "libelf missing: $(install_hint libelf)"
    fi
    if [ -d "/lib/modules/$(uname -r)/build" ]; then
        ok "kernel headers for $(uname -r)"
    else
        fail "kernel headers for $(uname -r) missing: $(install_hint kheaders)"
    fi
    ;;
*)
    note "unrecognized platform $platform; skipping OS-specific checks"
    ;;
esac

if [ "$status" -eq 0 ]; then
    printf 'environment looks good\n'
else
    printf 'Herr doctor found problems; CONTRIBUTING.md has the fixes\n'
fi
exit "$status"
