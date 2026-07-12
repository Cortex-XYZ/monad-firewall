# Contributing to monad-firewall

Thank you for your interest in contributing to `monad-firewall`! This project implements an ultra-high-performance eBPF/XDP firewall designed specifically to protect high-throughput blockchain validator infrastructure from network saturation, socket buffer exhaustion, and malicious port scanning.

By operating directly within the Linux kernel via eBPF, we drop or route malicious traffic before it ever hits the standard Linux socket buffer queues (`sk_buff`), mitigating context-switching overhead and preventing kernel panics under heavy load.

---

## 🏗️ Project Architecture

Our workspace enforces clean separation between kernel-space bytecode execution, shared memory layout, and user-space orchestration:

```text
.
├── monad-firewall-ebpf      # KERNEL SPACE: `no_std` BPF programs (XDP/TC entrypoints)
├── monad-firewall-common    # SHARED TYPES: `no_std` layout-compatible map structures
├── monad-firewall-core      # USER SPACE DRIVER: Aya-driven eBPF loader & link engine
├── monad-firewall-rules     # RULES ENGINE: Human-readable rules configuration & parser
├── monad-firewall-cli       # OPERATOR CLI: Command-line utility to query metrics & states
├── monad-firewall-server    # SERVICE DAEMON: Axum Web UI/IPC engine (Optional control plane)
├── monad-firewall-bench     # PROFILING: Criterion benchmarks & user-space map timing
├── monad-firewall-xtest     # INTEGRATION TEST SUITE: Generates & coordinates test topologies
└── xtask                    # AUTOMATION: Local development loop and compilation tasks
```

---

## 🛠️ Prerequisites & Setup

Because we compile Rust into eBPF bytecode targeting `bpfeb-unknown-none`, standard target management tools won't cut it. We use an explicit compilation pipeline via `xtask`.
### 1. Install System Dependencies

Select the command corresponding to your operating system to install the required LLVM toolchain, ELF development libraries, and kernel monitoring utilities:

#### Fedora / Red Hat
```bash
sudo dnf install clang llvm elfutils-libelf-devel bpftool kernel-devel
```

#### Ubuntu / Debian
```bash
sudo apt update
sudo apt install clang llvm libelf-dev linux-headers-$(uname -r) bpftool
```
*(Note: On certain Debian/Ubuntu LTS distributions, `bpftool` may instead be packaged inside `linux-tools-common` and `linux-tools-$(uname -r)`).*

#### Arch Linux
```bash
sudo pacman -Syu
sudo pacman -S clang llvm libelf bpf linux-headers
```
*(Note: On Arch Linux, the `bpftool` utility is contained within the core `bpf` package).*

#### macOS (Cross-Compilation & Toolchain Verification Only)
```bash
brew install llvm libelf
```

> ⚠️ **Important Note for macOS Contributors:**
> macOS does not run a Linux kernel natively. Installing these local dependencies is strictly to allow your local IDE toolchains (`rust-analyzer`) to cross-compile, parse, and verify codebase structures cleanly.
> 
> To ensure the Homebrew LLVM toolchain overrides Apple's default toolchain stubs, append it to your path:
> ```bash
> echo 'export PATH="/opt/homebrew/opt/llvm/bin:$PATH"' >> ~/.zshrc
> ```
> To actively run, inject, or run validation profiling against the firewall bytecode, macOS developers **must** utilize the automated Linux guest execution engine via `cargo xtask`.

### 2. Install BPF Linker
We use the specialized LLVM-based linker for Rust eBPF programs to emit valid ELF binaries that the kernel can verify:
```bash
cargo install bpf-linker
```

---

## 🚀 The Development Loop (`xtask`)

Do **not** run standard `cargo build` or `cargo check` from the workspace root. Our root configuration targets a localized subset of standard crates by default (`default-members`) to avoid environmental toolchain errors for non-eBPF work. All pipeline commands should flow through our custom `xtask` orchestrator.

### Building eBPF Bytecode & User Space
To compile the eBPF programs using specialized optimizations (`opt-level = 3` required by the kernel verifier) and link them back to the user-space loader, run:
```bash
cargo xtask build
```

### Running the Firewall Local Environment
XDP programs require `CAP_BPF` / `CAP_NET_ADMIN` privileges to interact with network interfaces. `xtask` automatically handles privilege escalations for local execution:
```bash
cargo xtask run -- --interface eth0
```

---

## 📝 Contribution Policies & Guardrails

### 1. Zero-Allocation in Kernel Space (`monad-firewall-ebpf`)
* The code inside `monad-firewall-ebpf` runs under a strict `no_std` target environment. 
* There is no allocator available. Absolutely no dynamic vectors (`Vec`), strings (`String`), or memory boxes (`Box`) are allowed. 
* Loops must be statically bounded and unrollable, otherwise the kernel verifier will flatly reject loading the bytecode.

### 2. ABI Compatibility in Shared Components (`monad-firewall-common`)
* Any structure containing network properties, IP patterns, or hit counters used in eBPF Maps **must** utilize explicit alignment attributes (`#[repr(C)]`).
* Never use types whose layouts vary across architectures or compiler profiles (e.g., standard pointer types or naked `usize`).

### 3. Rules Layer Abstraction (`monad-firewall-rules`)
* Contributions optimizing parsing logic or config interpretation belong exclusively inside `monad-firewall-rules`. The core daemon should only receive computed layouts ready to be mirrored into active BPF maps.

---

## 🤝 Pull Request Process

1. **Fork the Repository:** Create a feature branch off of `main`.
2. **Validate Your Changes:** Ensure your eBPF code passes verifier safety standards by running it locally through the `xtask` runner.
3. **Format & Lint:** Run `cargo fmt` across the workspace before opening a pull request.
4. **Document:** If adding a new configuration parameter or map logic, update the relevant `monad-firewall-docs` entry or the main `README.md`.
