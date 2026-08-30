# Math Playground — Single-Shot GOT Loop to Shell

**Competition:** BearCatCTF
**Category:** Pwn
**Techniques:** Unchecked function-pointer array index, GOT-value call primitive, self-induced re-entry via GOT redirect, staged GOT overwrite

## Target
A tiny 32-bit, no-PIE calculator: it reads an operator choice and two integers, then calls `operations[choice-1](a, b)` where `operations` is a fixed array of four function pointers (`add`/`subtract`/`multiply`/`divide`).

## Vulnerability
`choice` is never bounds-checked, so `operations[choice-1]` can index arbitrarily far outside the array — including backwards into the GOT, which sits right before `operations` in memory. A negative `choice` lands on a real GOT entry (`scanf`, `puts`, `__stack_chk_fail`, `printf`, …), and the program calls whatever address is stored there as a function, passing the next two integers you send as its two arguments. Since nothing has been overwritten yet on the first call, this means you can invoke `scanf`, `puts`, or any other still-intact libc function directly, with arguments you choose.

## Dead End: One Shot Isn't Enough
The obvious plan — leak a libc address, compute `system`'s address from it, then call `system("/bin/sh")` — needs at least two separate calls through the primitive, and the program only reads one choice and runs once before exiting. Overwriting the GOT entry that's about to be called doesn't help either: on the same call, the CPU has already fetched the *old* value. And even a successful GOT overwrite runs into an argument problem — redirecting `printf`'s GOT to `system`, for instance, still calls it with `printf`'s own first argument (a `"%d\n"` format string), not `"/bin/sh"`.

## Breakthrough: Loop Back Into `main` Through printf's GOT
The fix was to stop trying to finish the exploit in one call and instead make the "runs once" program run itself again. Calling through `scanf`'s (still-intact) GOT entry with arguments `("%d", printf_got)` performs a real `scanf` call that reads a new value from stdin directly into `printf`'s own GOT slot — and pointing that slot at an address inside `main`, right after its own `scanf("%d %d", &a, &b)` call, means the program's very next `printf("%d\n", res)` jumps back into the middle of `main` instead of returning. That turns a single-shot program into a multi-round primitive, all within one connection.

From there: a second round calls through `puts`'s GOT with `scanf`'s GOT address as the argument, leaking `scanf`'s real runtime address as raw bytes (and from it, the libc base and `system`'s address). A third round calls through `scanf`'s GOT again to overwrite `__stack_chk_fail`'s GOT entry with `system`'s address. A fourth round calls through that now-hijacked `__stack_chk_fail` GOT slot with the address of a `"/bin/sh"` string in libc as its argument — `system("/bin/sh")`, and a shell.

## Key Takeaway
An unchecked array index into a function-pointer table doesn't just give you arbitrary-function-call — indexing backwards onto the GOT turns *any* still-intact libc GOT entry into a callable primitive with attacker-controlled arguments. The real unlock here wasn't a new vulnerability, it was realizing the very same primitive could redirect execution back into the vulnerable code itself, turning a "runs exactly once" constraint into as many rounds as needed.

See `debug_log.md` for the dead-end reasoning (the four blocked attack paths considered before the GOT-redirect loop was found) — kept as-is because the stuck state is what makes the eventual trick worth explaining.
