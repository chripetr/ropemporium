## Solutions to ROP Emporium challenges

My solutions to [ROP Emporium challenges](https://ropemporium.com/) using **pwntools**.

Here are some useful tools that I used to accomplish the challenges:
*   [pwntools](https://github.com/Gallopsled/pwntools)
*   [gdb-peda](https://github.com/longld/peda)
*   objdump
*   readelf

All of the exploits where tested with __aslr enabled__.

**Note:** The *x86_shell.py* and *x64_shell.py* scripts spawn a shell while the *x86_exploit.py* and *x64_exploit.py* scripts print the flag.