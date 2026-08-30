# flytvast — Overwriting a Return Address Through Float-Only Input

**Competition:** undutmaning CTF
**Category:** Pwn
**Techniques:** Array-index-controlled out-of-bounds write, IEEE-754 bit-pattern encoding, ret2win

## Target

The binary reads a sequence of floating-point numbers from stdin into a fixed-size stack array and stops on an empty line. Each value is stored at `array[counter]`, and `counter` is itself derived from user-controlled state rather than being a simple, safely-bounded loop index.

## Vulnerability

By tracing the stack layout in GDB (`offset_calc.py`), the array, the loop counter, the stack canary, and the saved return address all sit at fixed, computable offsets from the array's base address, in the pattern `write_addr = array_base + (counter + 8) * 4`. Because `counter` itself can be set to an attacker-chosen value through one of the earlier float inputs, this turns a normal-looking "store a float at index counter" into an arbitrary 4-byte write at `array_base + 4 * (counter + 8)` — including past the end of the array, directly into the canary, the saved RBP, or the return address.

The catch is that every value sent to the program is parsed as an IEEE-754 float, not a raw integer or pointer. To land specific bytes at the return-address slot, the exploit needs to send inputs whose **bit pattern**, when interpreted as a `float`, spells out the address it wants written — not send the address as a number.

## Exploitation

`int_to_float()` does exactly that conversion: it packs a 32-bit integer and reinterprets those same 4 bytes as a `float`, so sending that float causes the program's own float-parsing/storage path to write back the original integer bits, untouched, into the target stack slot.

1. Four throwaway inputs (`1.1`, `2.2`, `3.3`, `4.4`) fill the array's safe region.
2. A fifth input sets `counter = 9` — computed via `offset_calc.py` to be the index whose target write address is the low 32 bits of the return-address slot.
3. A sixth input is `int_to_float(print_flag_address)` — its bit pattern is the address of `print_flag` (`0x004012b6`), so writing it overwrites the return address's low half with a valid code pointer.
4. A seventh input is `0.0` (whose bit pattern is all zero) to clear the return address's high 32 bits, since the target is a small, non-PIE address.
5. An empty line ends the input loop, the function returns, and control lands on `print_flag` instead of the caller.

## Key Takeaways

Type-level "safety" (the program only ever accepts floating-point numbers) doesn't stop a write primitive from being arbitrary — the exploit doesn't need the program to accept raw bytes or integers, only a way to steer the bit pattern of an accepted value. Reasoning about the exploit in terms of "which bits do I need at this address" rather than "which value do I need" is what makes bridging a floating-point-only interface into a classic ret2win possible.

---

Files in this folder:
- `offset_calc.py` — derives the `counter` value needed to target the canary, saved RBP, or either half of the return address, from GDB-observed stack addresses.
- `exploit.py` — the exploit run against the live remote instance (`undutmaning-flytvast.chals.io`), redirecting execution into `print_flag`.
