# AArch64 Kernel Binder Driver — MTE-Protected fd Theft (Partial, Post-Competition Reconstruction)

**Competition:** SekaiCTF
**Category:** Kernel Pwn / Binder IPC
**Techniques:** Reference-solver reverse engineering, Android Binder IPC internals, ARM Memory Tagging Extension (MTE) analysis, QEMU/AArch64 target debugging, Ghidra decompilation, confused-deputy file-descriptor confusion

## Objective

The challenge ships a custom AArch64 Linux kernel (booted under QEMU) with a modified Binder IPC driver and an added `mte_driver` kernel module that exercises ARM's Memory Tagging Extension. Two privileged userspace processes, `client` and `server`, talk to each other over `/dev/binder`. The intended goal is to make `client` lose control of a privileged file descriptor to an attacker-controlled process, and leverage that to reach the tagged-memory device and read the flag.

**I did not solve this challenge live during SekaiCTF.** This write-up documents a post-competition reconstruction: after the event ended, I got hold of the official author-provided reference solver executable for this challenge and reverse-engineered it (Ghidra decompilation plus manual disassembly reading — see `solver_reverse_notes.md`) to understand its approach, then tried to reproduce the fd-theft primitive it relies on in my own C solver.

## Environment & Methodology

- Extracted and booted the provided kernel `Image` + `initramfs.cpio.gz` under QEMU-aarch64, with `mte_driver.ko` loaded from `/lib/modules`, to have a live target to test against.
- Reverse-engineered the official reference solver binary in Ghidra to understand its overall approach: it first steals an `mte_driver` file descriptor from `server` via a custom UDP + Binder protocol, then hands off to a second, embedded binary that exploits a kernel use-after-free in `mte_driver`'s own allocate/free ioctls to get an arbitrary write and hijack `modprobe_path` for root code execution.
- In parallel, reverse-engineered the `client` binary's own fd bookkeeping in Ghidra: it closes every fd ≥ 3 via `close_range()`, then deterministically reopens `/dev/binder`, a `memfd`, a Unix socket, and several pipes in a fixed order — so fd numbers for a fresh `client` process are predictable and can be targeted precisely.
- Cross-referenced the kernel's Binder transaction path (`binder_transaction`, `binder_transaction_buffer_release`) directly against the kernel image in Ghidra to pin down the exact mechanism the reference solver's first stage depends on, and confirmed this kernel reorders the fields of `binder_fd_array_object` compared to upstream Linux.

## Vulnerability

The fd-theft primitive the reference solver's first stage relies on, as reconstructed from reverse-engineering it: when a Binder target process is **frozen** (`BINDER_FREEZE`) and then receives a transaction that **supersedes** an already-queued one (`TF_UPDATE_TXN`), the kernel releases the *superseded* transaction's buffer in the context of whichever process is currently making the call — not the original sender. If that superseded buffer still carries a `BINDER_TYPE_FDA` (file-descriptor array) object, `binder_transaction_buffer_release()` calls `close_fd()` on it, and `close_fd()` (via `sp_el0`) always operates on the *current* task's fd table.

By having the attacker (`solver`) queue a transaction against the frozen `server` that plants a stale fd reference, then having `client` itself issue a transaction that supersedes it, the kernel can be tricked into closing one of `client`'s own live fds — its control-channel socket — from inside `client`'s own syscall context.

An earlier hypothesis — based only on disassembly of the frozen-transaction handler — suspected the buffer release happened directly inside that handler. It was superseded after cross-checking the kernel's actual C source, which pinned the real trigger down to the `TF_UPDATE_TXN` supersede path. That correction mattered for reliably reproducing the primitive under GDB.

## What was confirmed

The confused-deputy fd-theft primitive itself was reproduced against the live QEMU target: queuing a stale-fd transaction against the frozen `server`, then triggering `client`'s own transaction to supersede it, does cause `close_fd()` to run inside `client`'s context and close its control-socket fd — verified with GDB breakpoints on the driver's open/ioctl entry points to confirm the race actually lands where expected. Re-filling the freed slot via `SCM_RIGHTS` with an attacker-chosen descriptor also worked, at the level of "the fd table entry now points where I want it to."

## What wasn't finished

Turning "client now holds an attacker-supplied fd where it expects its own socket" into an actual flag read was not completed — the reference solver's second stage (the embedded `racer_scc` binary, exploiting a kernel use-after-free in `mte_driver`'s allocate/free ioctls to overwrite `modprobe_path`) was not reproduced. Separately, an alternate route was explored on the `mte_driver` module directly — a kmalloc-96 use-after-free reachable through its allocate/free ioctls, with the idea of grooming a freed chunk to be reused as a `struct cred` and flipping a capability bit to gain `CAP_DAC_OVERRIDE` — but this stayed at the hypothesis stage (heap-spray reliability against the exact reuse target was never nailed down), and no flag was recovered through either path.

## Key Takeaways

Kernel IPC frameworks that let a third party interact with two other processes' state — like Binder's freeze/transaction-supersede machinery — can create confused-deputy conditions even when neither endpoint has a "traditional" memory-safety bug. The vulnerability here is entirely about *whose context* a cleanup routine runs in, not a buffer overflow, and reproducing that primitive reliably (getting the race and the slot-shifted Binder responses to line up under GDB) was itself the bulk of the work, even working from a reference solver rather than from scratch. This challenge was also a good exercise in methodology: an initial disassembly-only theory of the bug turned out to be wrong, and cross-checking against the kernel's actual C source (rather than trusting the decompiler at face value) was necessary to find and fix that mistake.

---

Files in this folder:
- `analysis_notes.md` — reverse-engineering notes on the client/server fd layout and the Binder release path, including the correction described above.
- `solver_reverse_notes.md` — annotated understanding of the official reference solver's logic, reconstructed from Ghidra decompilation and manual disassembly reading after the competition ended.
- `solver.c` — my own attempted C reproduction of the fd-theft primitive.
