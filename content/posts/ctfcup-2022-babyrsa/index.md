+++
title = 'Russian CTF Cup 2022 — babyrsa'
date = 2022-12-11T08:02:32+03:00
tags = ['ctf', 'writeup', 'crypto']
toc = true
tldr = 'collect impossible remainders and use CRT to retrieve RSA factor'
+++

## Source code

Full source code is available here: [https://github.com/HackerDom/ctfcup-2022-battles/blob/master/main-pack/crypto/](https://github.com/HackerDom/ctfcup-2022-battles/blob/master/main-pack/crypto/)

- **server.py**

```python
#!/usr/bin/env python3

import os
import cmd
import sys
import random
import secrets
import collections

import gmpy2


FLAG = os.getenv('FLAG', 'Cup{*********************************************}').encode()
assert len(FLAG) == 50


RSA = collections.namedtuple('RSA', ['e', 'n', 'p', 'q'])


class Dummy:
    def __getattribute__(self, _):
        raise Exception('key is not generated')


class Challenge(cmd.Cmd):
    intro = 'Welcome to babyrsa-2022 challenge. Type help or ? to list commands.\n'
    prompt = '> '

    key = Dummy()

    def onecmd(self, line):
        line = line.lower()

        if line == 'eof':
            sys.exit(0)

        try:
            return super().onecmd(line)
        except Exception as e:
            return print(f'ERROR: {e}')

    def do_generate(self, _):
        'Generate new RSA key:  GENERATE'
        self.key = self._generate_key(512)

    def do_key(self, _):
        'Print the RSA public key:  KEY'
        print(self.key.e)
        print(self.key.n)

    def do_hint(self, _):
        'Print a hint for RSA:  HINT'
        hint = self._get_hint()
        print(hint)

    def do_flag(self, _):
        'Print the encrypted flag:  FLAG'
        secret = secrets.token_bytes(8)
        plaintext = self._to_number(FLAG + b'\x00' + secret)
        ciphertext = self._encrypt(plaintext)
        print(ciphertext)

    def do_encrypt(self, arg):
        'Encrypt a number using RSA key:  ENCRYPT 12345'
        plaintext = int(arg)
        ciphertext = self._encrypt(plaintext)
        print(ciphertext)

    def do_super(self, arg):
        'Super encrypt a number using RSA key:  SUPER 12345'
        plaintext = int(arg)
        ciphertext = self._super_encrypt(plaintext)
        print(ciphertext)

    def do_exit(self, _):
        'Exit from challenge:  EXIT'
        sys.exit(0)

    def _random_prime(self, bits):
        rnd = random.getrandbits(bits)
        return int(gmpy2.next_prime(rnd))

    def _generate_key(self, bits):
        e = 65537
        p = self._random_prime(bits)
        q = self._random_prime(bits)
        n = p * q
        return RSA(e, n, p, q)

    def _get_hint(self):
        return self.key.p - self._to_number(FLAG)

    def _encrypt(self, plaintext):
        return pow(plaintext, self.key.e, self.key.n)

    def _super_encrypt(self, plaintext):
        exponent = self._to_number(FLAG)
        return pow(plaintext, exponent, self.key.n)

    def _to_number(self, data):
        return int.from_bytes(data, 'big')


def main():
    challenge = Challenge()
    challenge.cmdloop()


if __name__ == '__main__':
    main()
```

## Solution

The challenge implements RSA encryption, we're also given a number $hint = p - flag$. In fact the solution implies only using the $hint$ number, the other features of the task is not needed.

It's well-known that $p$ is a prime number (as one of RSA factors). Let's take a small prime number $prime < p$. Since $p$ is a prime number there is a property:

$$p \neq 0 \pmod{prime}$$

Let's use an identity:

$$hint = p - flag \pmod{prime}$$

From this identity it's obvious that the case $hint = -flag \pmod{prime}$ is impossible. Therefore, since the $flag$ is constant, the number $hint \pmod{prime}$ could be any number from $[0,\ prime)$ except for $-flag \pmod{prime}$.

We could use this information to solve the challenge:

- take some different $prime$ numbers
- for each $prime$ we save the set of remainders from $[0,\ prime)$
- continuously generate RSA keys and take $hint$ from challenge
- for each $prime$ remove $-hint \pmod{prime}$ from the set of remainders
- at some point in each set will be the only element $flag \pmod{prime}$
- use chinese remainder theorem to reconstruct $flag$

We could use multithreading in order to parallel queries.

## Example solver

```python
#!/usr/bin/env python3

import sys
import time
import threading

import client


HOST = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 17171

PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999]


# https://gist.github.com/eyuelberga/86a7fdf9583701b68f609284efdbf2a1
def CRT(mn, an):
    m = 1
    Mn = []
    yn = []
    for k in range(0, len(mn)):
         m  = m * mn[k]
    
    for  k in range (0, len(mn)):
        Mk = m // mn[k]
        Mn.append(Mk)
        yk = pow(Mn[k], -1, mn[k]) % mn[k]
        yn.append(yk)
    x = 0
    for  k in range (0, len(yn)):
        x = x + an[k] * Mn[k] * yn[k]
    while x >= m:
        x = x - m
    return x


def attack(hints):
    leaks = {prime: set(range(prime)) for prime in PRIMES}
    target = 50 * 8  # len(flag) * 8

    used = 0

    while True:
        while len(hints) == 0:
            time.sleep(0.01)

        hint = hints.pop()
        used += 1

        modulus = 1

        for prime in leaks:
            leak = (-hint) % prime

            if leak in leaks[prime]:
                leaks[prime].remove(leak)

            if len(leaks[prime]) == 1:
                modulus *= prime

        if modulus.bit_length() >= target:
            break

        if used % 100 == 0:
            print(
                f'Used hints: {used}, '
                f'Modulus: {modulus.bit_length()} bits'
            )

    print(f'Found modulus of size {modulus.bit_length()} bits')

    values, modules = [], []

    for prime, leak in leaks.items():
        if len(leak) > 1:
            continue

        values.append(leak.pop())
        modules.append(prime)

    flag = CRT(modules, values)

    return flag.to_bytes(target // 8, 'big')


def collect(hints):
    cli = client.Client(HOST, PORT)

    try:
        while True:
            cli.generate()

            hint = cli.hint()
            hints.append(hint)
    finally:
        cli.exit()


def main():
    count = 50
    hints = []

    for _ in range(count):
        thread = threading.Thread(
            target = collect, args = [hints], daemon = True,
        )

        time.sleep(0.1)
        thread.start()

    flag = attack(hints)
    print(flag)


if __name__ == '__main__':
    main()
```
