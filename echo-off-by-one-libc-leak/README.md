# echo — Off-by-One Leak Chain Through a Full-RELRO/CET Binary

**Competition:** srdnlen CTF
**Category:** Pwn
**Techniques:** Off-by-one buffer overflow, progressive stack-frame leaking, PIE/canary/libc defeat without a `pop rdi` gadget, Intel CET (SHSTK/IBT) compatible ROP

## Target

A tiny "echo" service: it reads up to `local_18` (initially `0x40 = 64`) bytes into a 64-byte stack buffer one byte at a time, then `puts()`s whatever it read. Protections are about as tight as a stack-based pwn challenge gets: Full RELRO (GOT is read-only), stack canary, NX, PIE, and Intel CET (Shadow Stack + Indirect Branch Tracking).

## Vulnerability

`read_stdin()`'s stop condition is `local_18 >= counter`, checked *after* each byte is stored — so when `counter` reaches `local_18` it still reads one more byte before stopping. That 65th byte lands exactly on `local_18` itself, one byte past the 64-byte buffer. Overwriting it lets you raise the read limit for the *next* round, and repeating this across rounds walks the readable/writable window forward through the stack: padding, then the canary, then the saved RBP, then the return address, one controlled step at a time. Because a natural stop (hitting the byte-count limit) never writes the terminating `\x00` that a `\n`-triggered stop would, `puts()` keeps printing straight through whatever comes next on the stack — turning the overflow into a leak primitive for free.

Six rounds of this get you, in order: the off-by-one activation, a clean non-zero padding fill (so `puts` doesn't stop early on stack garbage), the canary, the saved RBP, the PIE-relative return address, and enough room to send a much larger payload later.

## Dead End: Fake RBP Into the GOT

To leak libc without a `pop rdi` gadget (there isn't one in this binary), the first working idea was to abuse the exact instruction sequence at `echo+0x69` — `lea rax, [rbp-0x50]; mov rdi, rax; call puts` — by overwriting the saved RBP with a **fake** value: `puts_got + 0x50`. That makes `rbp - 0x50` land exactly on `puts@GOT`, so the forged return into `echo+0x69` executes `puts(puts@GOT)` and leaks the real libc address of `puts`. This part worked immediately.

The problem showed up right after: with the frame's RBP now pointing into the GOT, the *next* round's buffer (`rbp - 0x50` again) also points into the GOT — which Full RELRO makes read-only. Any further byte written by `read_stdin()` (even just the natural loop reading the next round's input) SIGSEGVs immediately, because it's trying to write into read-only memory. Leaking libc this way permanently traps the process in a GOT-backed frame with no way to send a second-stage payload — confirmed by checking the actual GOT layout (`puts_got + 0x40`, where `local_18` would live, is `0`, which independently explains why the loop can't take more input either way). `debug_log.md` walks through this dead end and the half-dozen variations tried before abandoning it (stack-pivoting, SROP, ret2dl-resolve, format-string — none panned out with what this binary offers).

## Breakthrough: Leak Through `main`'s Own Frame Instead

The fix was to stop trying to leak libc through the GOT at all. By continuing to push the off-by-one window forward — past `echo`'s own return address into the caller's (`main`'s) stack frame — one of `main`'s local stack slots turns out to hold `__libc_start_call_main+128`, a real libc code address, sitting in plain, writable stack memory. Leaking that instead sidesteps the GOT entirely: the frame stays on the stack, still fully writable, so a second overflow in the very same connection is no longer a problem.

With libc's base address known, the final round overwrites the return address slot directly with a `ret; pop rdi; ret; system` ROP chain (CET-compatible — no indirect-branch violations, since every transfer is a `ret`) pointing at `"/bin/sh"`, giving a shell in a single additional round.

## Exploitation Summary

1. Off-by-one activates (`local_18`: `0x40 → 0x80`).
2. Pad the gap with non-zero bytes so later leaks aren't cut short by stack garbage.
3–5. Leak the canary, saved RBP, and PIE-relative return address, one stack qword at a time, restoring the single byte each round overwrites to trigger its own stop condition.
6. Extend `local_18` again and leak `__libc_start_call_main+128` out of `main`'s frame → compute the libc base.
7. Overwrite canary (correct value) + saved RBP + a `pop rdi; ret; system("/bin/sh")` chain in the return-address slot → shell.

See `exploit.py` for the full, working implementation (retries automatically on any ASLR-dependent leak that comes back short or contains a stray `\n`), and `debug_log.md` for the real-time debugging notes from the dead-end attempt, kept as-is because the wrong turn is as informative as the fix.
