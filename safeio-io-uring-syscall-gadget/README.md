# Safeio — Bypassing seccomp with a Hidden Syscall Gadget + io_uring Side Channel

**Competition:** AIS3 EOF CTF
**Category:** Pwn
**Techniques:** seccomp bypass via a hidden `syscall; ret` gadget, io_uring-only exploitation, timing side-channel oracle, binary search

## Target
The service forks into two processes. The parent holds a Unix socket and is locked down to `read`/`write`/`exit` via seccomp. The child accepts arbitrary shellcode (up to 0x1000 bytes), scans it for the raw `syscall` opcode (`0f 05`) and refuses to run it if found, then executes it under a seccomp filter that only allows `io_uring_setup`/`io_uring_enter`/`exit`. The goal is to read `flag.txt`, but the parent never echoes back anything the child sends it, so there's no direct way to see what the child reads.

## Vulnerability
The binary ships a small, seemingly-unused function: `magic() { return -859634417; }`, compiled down to `mov eax, 0xccc3050f; ret`. The three bytes at `magic+5` happen to be `0f 05 c3` — `syscall; ret` — a gadget the shellcode scanner never looks at, since it only inspects the shellcode buffer itself, not the binary's own code. Because PIE is enabled but the return address to `main()` is sitting on the stack at a fixed offset when the shellcode starts running, the gadget's address is computable at runtime as `[rsp+0x20] + 0x765`, with no separate leak needed.

## Approach
With a way to issue arbitrary syscalls again, the remaining constraint is that only `io_uring_setup`/`io_uring_enter` are allowed by the child's seccomp filter — so the shellcode has to build every io_uring structure (params, SQEs, completion ring) by hand in the mapped scratch memory, submit an `IORING_OP_OPENAT` for `flag.txt`, then an `IORING_OP_READ` into a known buffer offset.

Since the parent never surfaces the child's output, the exploit reads `flag.txt` into memory and turns the comparison into a timing oracle instead of a leak: shellcode compares a target byte against a guessed value, and on a match spins in an infinite loop (visible to the exploit as a timeout) while a mismatch lets the process exit normally (visible as a fast response). A per-character binary search over the printable range narrows each byte down in about 7 attempts instead of a full 95-value scan, with a known flag prefix (`EOF{hope_...`) skipping the characters that don't need guessing, plus retries and majority-vote confirmation to absorb the remote connection's occasional instability.

## Key Takeaway
A "harmless" unused function turned out to hide exactly the three bytes needed to defeat a syscall-opcode scanner, and the absence of a direct output channel didn't stop a timing side channel from doing the same job — just more slowly. Binary search made the difference between a brute force that's impractical over a network and one that finishes comfortably.

## Flag
```
EOF{hope_%999999999s_llm_can't_solve_this_not_safe_io_uring}
```
