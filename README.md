# CTF Write-ups — Selected Highlights

A small, curated selection of especially interesting challenges I've solved across a few public and university CTFs — picked out as the ones I found most interesting or still remember clearly, not a complete record of every event I've played. (Coursework-based write-ups live in a separate repo, [security-coursework-portfolio](../security-coursework-portfolio).)

## Challenges

| Challenge | Competition | Category | Techniques |
|---|---|---|---|
| [AArch64 Kernel Binder fd Theft (Partial, Reconstruction)](./mte-kernel-binder-fd-theft) | SekaiCTF | Kernel Pwn | Reference-solver reverse engineering, Binder IPC internals, ARM MTE, QEMU debugging |
| [echo — Off-by-One Leak Chain](./echo-off-by-one-libc-leak) | srdnlen CTF | Pwn | Off-by-one overflow, progressive stack leaking, Full RELRO/PIE/canary/CET defeat |
| [flytvast — Float-Encoded Overwrite](./flytvast-float-encoded-overwrite) | undutmaning CTF | Pwn | Array-index-controlled OOB write, IEEE-754 bit-pattern encoding, ret2win |
| [Math Playground](./math-playground-got-loop-primitive) | BearCatCTF | Pwn | Unchecked function-pointer index, GOT-value call primitive, self-induced re-entry loop |
| [ooonenooote — musl FSOP Double Pivot](./ooonenooote-musl-fsop-double-pivot) | AIS3 EOF CTF | Pwn | Signed-index OOB write, musl libc FSOP hijack, double stack pivot, syscall ROP |
| [Safeio — io_uring Syscall Gadget](./safeio-io-uring-syscall-gadget) | AIS3 EOF CTF | Pwn | Hidden syscall gadget, seccomp bypass, io_uring exploitation, timing side channel |

## A Note on These Write-ups

These write-ups were organized some time after actually solving (or, in one case, attempting) each
challenge, based on my own notes from the time. I've tried to keep every technical detail accurate
against those original records, but some specifics may be slightly off given the gap in time.

## Tools

Ghidra, GDB/pwndbg, QEMU, pwntools
