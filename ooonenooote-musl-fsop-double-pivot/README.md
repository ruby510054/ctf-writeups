# ooonenooote — musl libc FSOP Double Stack Pivot

**Competition:** AIS3 EOF CTF
**Category:** Pwn
**Techniques:** Signed-integer negative-index OOB write, musl libc FSOP (`close_file` hijack), double stack pivot, syscall ROP

## Target
A statically-linked musl libc binary. It lets the user pick a slot in a 16-entry `notes` array by index, allocate a 128-byte heap chunk there, and write into it.

## Vulnerability
The bounds check only rejects `choice > MAX_LEN` — it never checks for negative values. Since `choice` is a signed int, any negative index passes the check, letting `notes[choice]` write past the start of the array into whatever stack memory sits before it.

## Approach
With PIE disabled, every address is fixed. Scanning the stack slots reachable through negative indices turned up several that happen to hold `0x40e140` — the address of musl's `__stdout_FILE` structure in `.data`, left there as a leftover pointer from libc's own startup code. `notes[-108]` was one of them: writing there plants a heap-chunk pointer directly at that stack slot, and reading into it lets the 128-byte write land on `stdout`'s own `FILE` struct.

musl's `exit()` walks its list of open file streams and calls `close_file` on each. Inside `close_file`, if the byte at `FILE+0x28` differs from the one at `FILE+0x38`, it calls a function pointer stored at `FILE+0x48` with `rdi` pointing at the `FILE` struct itself — a direct hijack of control flow, gated by two conditions: the lock field at `+0x8c` must stay negative (it does, since offset 140 is out of the 128-byte write's reach, so it keeps its original `0xffffffff`), and `+0x28` must differ from `+0x38`.

Only 128 bytes to work with, and `rdx` starts out non-zero, ruled out a direct ROP chain. The fix was a double stack pivot: `FILE+0x48` holds a `leave; ret` gadget, which uses the RBP value pre-planted at offset `0x00` to move `rsp` to offset `0x50`; the very next instruction executed is a second gadget (`pop rax; pop rdx; add rsp, 0x28; ret`) that zeroes `rdx` and skips over the fake-buffer fields to land back on the same `leave; ret` at `0x48` — which fires a second time and finally settles `rsp` onto the real ROP chain at `0x50`. From there it's a standard `pop rdi; ret` → `"/bin/sh"` → `pop rax; ret` → `59` → `syscall; ret` to get `execve("/bin/sh", NULL, NULL)`.

## Key Takeaway
A single missing negative-value check on an array index, combined with a stray libc-internal pointer left sitting on the stack, was enough to reach and hijack a `FILE` structure's exit-time cleanup path — no heap-metadata corruption required. The double stack pivot only exists because there wasn't room in one 128-byte write for the register setup and the full ROP chain at once.

## Flag
```
EOF{I_accidently_found_this_unintended_solution_in_an_EZ_challenge_Lol_Hope_you_find_this_cool_lol_2e4e0fe9d5c9ae14bc7ec9}
```
