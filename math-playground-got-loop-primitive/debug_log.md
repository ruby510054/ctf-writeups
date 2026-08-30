# Math Playground CTF - 分析筆記（更新版）

## 題目概覽

- **題型**：Pwn（Binary Exploitation）
- **架構**：i386-32-little（32-bit Linux）
- **Binary**：`math_playground`
- **題目提示**：*"the layout of the program on remote may be slightly different"*

## 保護機制

| 保護 | 狀態 | 影響 |
|------|------|------|
| PIE | ❌ 關閉 | Binary 位址固定（`0x8048000`），可預測 |
| NX | ✅ 開啟 | Stack 不可執行，無法直接跑 shellcode |
| Stack Canary | ✅ 開啟 | Stack overflow 受限，無法改 return address |
| RELRO | Partial | GOT 表**可寫** |

## 漏洞分析

### 程式邏輯

```c
int (*operations[4])(int, int) = {add, subtract, multiply, divide};
res = (*operations[choice-1])(a, b);   // 沒有邊界檢查！
```

### 漏洞：Out-of-Bounds Array Access

`choice` 沒有做邊界檢查，輸入任意整數可讓程式把任意記憶體位址的內容當成函式指標來呼叫。

```
eax = memory[operations + (choice - 1) * 4]
    = memory[0x804c02c + (choice - 1) * 4]
```

### Call eax 當下的 Stack 結構

```asm
push ecx    ← b（第二個整數輸入）
push edx    ← a（第一個整數輸入）
call *eax   ← 呼叫目標函式，同時 push return address 0x080492cc
```

### Call eax 之後的流程

```asm
0x080492cc: add esp, 0x10
0x080492cf: mov [ebp-0x10], eax    ← 存回傳值
0x080492d5: push [ebp-0x10]        ← 回傳值當參數
0x080492d8: push 0x804a081         ← "%d\n" 字串
0x080492dd: call printf@plt        ← 印出結果（第二次函式呼叫！）
0x080492e2: add esp, 0x10
0x080492e5: mov eax, 0
0x080492ed: sub edx, gs:0x14       ← canary 檢查
0x080492f6: call __stack_chk_fail  ← canary 壞掉才會呼叫
0x080492fb: ...
0x08049302: ret
```

**重要：call eax 之後還有一次 `call printf@plt`，以及 canary 失敗時的 `call __stack_chk_fail`。**

## 關鍵位址（Binary，固定，No PIE）

| 符號 | 位址 |
|------|------|
| `operations` 陣列 | `0x0804c02c` |
| `main` | `0x080491e6` |
| `call eax`（漏洞觸發點）| `0x080492ca` |
| `"%d\n"` 字串 | `0x804a081` |
| `"%d"` 格式字串（scanf 用）| `0x804a064` |
| `"%d %d"` 格式字串 | `0x804a07b` |

## GOT 表與 Choice 對應

| 函式 | GOT 位址 | Choice 值 |
|------|----------|-----------|
| `__libc_start_main` | `0x804c00c` | -7 |
| `printf` | `0x804c010` | -6 |
| `__stack_chk_fail` | `0x804c014` | -5 |
| `puts` | `0x804c018` | -4 |
| `setvbuf` | `0x804c01c` | -3 |
| `__isoc99_scanf` | `0x804c020` | -2 |

**初次執行時 GOT 內是 PLT stub（lazy binding），函式被呼叫後才填入真實 libc 位址。**

## Remote 環境：ASLR 關閉！

Dockerfile 被註解掉的實際執行指令：
```dockerfile
./ynetd -t 60 -lt 10 -lm 33554432 -p 5000 -u ctf 'linux32 -R ./math_playground'
```

`linux32 -R` = **關閉 ASLR**，所有位址固定！

## Libc 資訊（容器內 `/lib32/libc.so.6`）

| 符號 | Offset | 固定位址（libc base = `0xf7d93000`）|
|------|--------|--------------------------------------|
| `system` | `0x0004c8d0` | `0xf7ddf8d0` |
| `printf` | `0x00053f10` | `0xf7de6f10` |
| `__isoc99_scanf` | `0x0005a410` | `0xf7ded410` |
| `/bin/sh` 字串 | `0x001b5faa` | `0xf7f48faa` |

### 關鍵 Offset 差距

```
system - printf = 0x4c8d0 - 0x53f10 = -0x7640
system - scanf  = 0x4c8d0 - 0x5a410 = -0xdb40
```

### `/bin/sh` 轉成 signed int

```python
import ctypes
ctypes.c_int32(0xf7f48faa).value  # = -136,413,014（需確認）
```

**注意：`scanf("%d")` 讀 signed int，大於 INT_MAX 的位址要轉成負數才能傳入。**

## 已確認的事實

- ✅ choice=-6 → eax = printf 真實位址，漏洞確認可用
- ✅ choice=-7 → eax = __libc_start_main，跳過去會 SIGSEGV（不可用）
- ✅ ASLR 關閉後 libc base 固定為 `0xf7d93000`
- ✅ 記憶體中找不到任何地方存著 system 的位址（`find` 搜尋為空）
- ✅ Operations 正數方向（choice=5）後面是 stdout，值為 0 或 `0xf7fb0da0`（環境不同）
- ✅ binary 內沒有 `/bin/sh` 字串
- ❌ 無法透過 choice 直接跳到 system（GOT 裡沒有 system entry）
- ❌ 無法透過 stack overflow 改 return address（有 canary）
- ❌ 跳到 binary text 段（no PIE 雖然固定，但 offset 不是 4 的倍數，choice 跳不到）

## 核心困境

| 需求 | 狀態 | 說明 |
|------|------|------|
| eax = system | ❌ | GOT 裡沒有 system，記憶體中也找不到存 system 位址的地方 |
| a = /bin/sh 位址 | ⚠️ | 位址固定但需轉成負數，且要搭配正確的 eax |
| 兩步驟攻擊（leak + exploit）| ❌ | 程式只跑一次 |

## 可能的攻擊路徑（待驗證）

### 路徑 A：GOT 改寫（兩次呼叫）

1. choice=-2 → 呼叫 scanf(a, b)
2. a = `"%d"` 格式字串位址，b = printf GOT 位址（`0x804c010`）
3. 輸入 system 位址的 signed int 值，把 printf GOT 改成 system
4. 後續 `call printf@plt` 自動變成 `call system`
5. **問題**：system 收到的第一個參數是 `0x804a081`（"%d\n"），不是 /bin/sh

### 路徑 B：直接呼叫 system（如果能找到 eax = system 的方法）

1. eax = system（需要在記憶體某處找到存有 system 位址的地方）
2. a = /bin/sh 位址（signed int 形式）
3. **問題**：目前找不到存有 system 位址的記憶體位置

### 路徑 C：__stack_chk_fail GOT 改寫

1. 用 scanf 把 `__stack_chk_fail` GOT 改成 system
2. 想辦法觸發 canary 失敗
3. canary 失敗 → 呼叫 `__stack_chk_fail` → 實際呼叫 system
4. **問題**：canary 失敗需要 stack overflow，但你沒有 overflow 能力；且 system 的參數也不對

### 路徑 D：ret2plt + 兩次執行

1. 找辦法讓程式重新執行 main
2. 第一次：leak libc 位址
3. 第二次：呼叫 system
4. **問題**：Binary text 段的位址和 operations 的差距不是 4 的倍數，choice 跳不到 main

## 待驗證的問題

- [ ] 路徑 A 中，`scanf` 被當函式呼叫時（call eax = scanf），它的回傳值是什麼？回傳值之後會被 printf 印出，有沒有利用價值？
- [ ] 有沒有辦法讓 system 的參數變成有用的字串？例如找一個 libc 內 `"sh"` 字串的固定位址？
- [ ] Remote 環境的 libc base 是否真的是 `0xf7d93000`？還是不同？
- [ ] 有沒有其他 libc 函式可以直接讀出 flag（例如某種 open/read gadget）？