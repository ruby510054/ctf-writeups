import struct

# From GDB output (these are concrete addresses we observed)
local_48_start = 0x7ffd5949b740   # rbp-0x40, where array starts
counter_addr   = 0x7ffd5949b770   # rbp-0x10, where local_18 lives
canary_addr    = 0x7ffd5949b778   # rbp-0x08
ret_addr       = 0x7ffd5949b788   # rbp+0x08

# Formula: write_addr = local_48_start + (counter + 8) * 4
# Solve for counter: counter = (target - local_48_start) / 4 - 8

def needed_counter(target_addr):
    offset = target_addr - local_48_start
    assert offset % 4 == 0, "not 4-byte aligned!"
    index = offset // 4
    counter = index - 8
    return counter

print(f"counter to hit counter_addr : {needed_counter(counter_addr)}")
print(f"counter to hit canary_addr  : {needed_counter(canary_addr)}")
print(f"counter to hit ret_addr lo  : {needed_counter(ret_addr)}")
print(f"counter to hit ret_addr hi  : {needed_counter(ret_addr + 4)}")