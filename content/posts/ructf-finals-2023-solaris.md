+++
title = 'RuCTF Finals 2023 — solaris'
date = 2023-04-25T00:00:00+03:00
tags = ['ctf', 'writeup', 'crypto']
toc = true
+++

The source code is available here: [https://github.com/HackerDom/ructf-finals-2023/tree/master/services/solaris](https://github.com/HackerDom/ructf-finals-2023/tree/master/services/solaris).

## Description

The service was named after [Solaris](https://en.wikipedia.org/wiki/Solaris_(1972_film)) — a 1972 Soviet science fiction movie directed by [Andrei Tarkovsky](https://en.wikipedia.org/wiki/Andrei_Tarkovsky).

## Cryptosystem

Prepare parameters:

1. Generate an RSA modulus $N = p \cdot q$ (where $p$ and $q$ are prime integers). Integers modulo $N$ form ring $\mathbb{R}$

2. Declare $\mathbb{MS}$ — space of all matrices $n \times n$ over the ring $\mathbb{R}$

3. Select some random invertible matrices $A = \{A_1, A_2, ..., A_k\}$ from $\mathbb{MS}$

4. Use $N$ as a public key and $A$ as a private key

Declare operation $MASK(m)$:

1. Select $r = (r_1, r_2, ..., r_{n-1})$ as random elements from $\mathbb{R}$

2. Create diagonal matrix $M$ using vector $(m, ...r)$

3. Return $M$

Declare operation $UNMASK(M)$:

1. Return $m$ as top-left element of matrix $M$

Let's say we have to encrypt a message $m$. Encryption and decryption operations:

$$
\begin{aligned}
C = Enc(m) &= A^{-1} \cdot MASK(m) \cdot A = \\\
           &= A_k^{-1} \cdot ... \cdot A_2^{-1} \cdot A_1^{-1} \cdot MASK(m) \cdot A_1 \cdot A_2 \cdot ... \cdot A_k
\end{aligned}
$$

$$
\begin{aligned}
m = Dec(C) &= UNMASK(A \cdot C \cdot A^{-1}) = \\\
           &= UNMASK(A_1 \cdot A_2 \cdot ... \cdot A_k \cdot C \cdot A_k^{-1} \cdot ... \cdot A_2^{-1} \cdot A_1^{-1})
\end{aligned}
$$

## Vulnerability

Suppose we want to decrypt ciphertext $C$ and recover plaintext $m$.

1. Take a [trace](https://en.wikipedia.org/wiki/Trace_(linear_algebra)) of matrix $C$ as a sum of main diagonal using [similarity invariance](https://en.wikipedia.org/wiki/Similarity_invariance)

$$t_1 = trace(C) = m + r_1 + r_2 + ... + r_{n-1}$$

We have a single equation of $n$ variables, where $n$ is the dimension of the matrix. Since we have $n$ variables, we need at least $n$ equations to solve the system.

2. Take traces of matrices $C^2, C^3, ..., C^n$

$$t_2 = trace(C^2) = m^2 + r_1^2 + r_2^2 + ... + r_{n_1}^2$$

$$t_3 = trace(C^3) = m^3 + r_1^3 + r_2^3 + ... + r_{n_1}^3$$

$$...$$

$$t_n = trace(C^n) = m^n + r_1^n + r_2^n + ... + r_{n_1}^n$$

Now we have the system of $n$ variables and $n$ equations. Let's look at the polynomial form:

$$pol_1(X, Y_1, Y_2, ..., Y_{n-1}) = X^1 + Y_1^1 + Y_2^1 + ... + Y_{n-1}^1 - t_1$$

$$pol_2(X, Y_1, Y_2, ..., Y_{n-1}) = X^2 + Y_1^2 + Y_2^2 + ... + Y_{n-1}^2 - t_2$$

$$...$$

$$pol_n(X, Y_1, Y_2, ..., Y_{n-1}) = X^n + Y_1^n + Y_2^n + ... + Y_{n-1}^n - t_n$$

3. Calculate the [Gröbner basis](https://en.wikipedia.org/wiki/Gr%C3%B6bner_basis) to get univariate polynomial

The calculated basis contains a univariate monic polynomial $P(W)$ over the ring $\mathbb{R}$:

$$P(W) = W^n + U_{n-1} \cdot W^{n-1} + U_{n-2} \cdot W^{n-2} + ... + U_2 \cdot W^2 + U_1 \cdot W + U_0$$

This polynomial contains all solutions for the system above:

$$P(m) = 0$$

$$P(r_1) = 0$$

$$P(r_2) = 0$$

$$...$$

$$P(r_{n-1}) = 0$$

We can't directly find roots of $P(W)$, because we don't know factorization of $N$.

4. Apply [Coppersmith method](https://en.wikipedia.org/wiki/Coppersmith_method) to get small roots

Service used:

- $N \approx 2048 \text{ bits}$
- $n = 6$
- $m \approx 256 \text{ bits}$ (RuCTF flag format)

Degree of $P(W)$ is $n$, so $m^n \approx 256 \times 6 \approx 1536 \text{ bits}$.

Fortunately $m^n < N$ so we can obtain $m$ as a small root of $P(W)$.

Example exploit: 

```python
#!/usr/bin/env sage

import re
import sys
import json
import dataclasses
from typing import Optional, Iterable

import requests


IP = sys.argv[1] if len(sys.argv) > 1 else None
PORT = 17173

FLAG_ID = sys.argv[2] if len(sys.argv) > 2 else None


@dataclasses.dataclass
class Keyspace:
    n: int
    m: int
    modulus: int


class Client:
    def __init__(self, ip: str, port: int) -> None:
        self.url = f'http://{ip}:{port}'

    def get_keyspace(self, username: str) -> Optional[Keyspace]:
        url = f'{self.url}/api/storage/keyspace'
        params = {
            'username': username,
        }

        resp = requests.get(url, params = params)

        if resp.status_code != 200:
            return None

        return self.parse_keyspace(resp.text)

    def get_ciphertext(self, ciphertext_id: str) -> Optional[Matrix]:
        url = f'{self.url}/api/storage/ciphertext'
        params = {
            'id': ciphertext_id,
        }

        resp = requests.get(url, params = params)

        if resp.status_code != 200:
            return None

        return self.parse_ciphertext(resp.text)
    
    def parse_keyspace(self, content: str) -> Keyspace:
        parts = re.findall(r'\d+', content)

        n = int(parts[0])
        m = int(parts[1])
        modulus = int(parts[2])

        return Keyspace(n, m, modulus)
    
    def parse_ciphertext(self, content: str) -> Matrix:
        obj = json.loads(content)

        matrix = []

        for element in obj:
            row = []

            for value in element:
                row.append(int(value, 10))

            matrix.append(row)

        return Matrix(matrix)


def attack(keyspace: Keyspace, ciphertext: Matrix) -> Iterable[bytes]:
    d = keyspace.n
    N = keyspace.modulus

    R = Zmod(N)
    MS = MatrixSpace(R, d, d)

    P = PolynomialRing(R, ', '.join(['x'] + [f'r{i}' for i in range(d - 1)]))
    x, *r = P.gens()

    matrix = MS(ciphertext)

    pols = [
        x^i + sum(ri^i for ri in r) - (matrix ^ i).trace()
        for i in range(1, d + 1)
    ]

    I = Ideal(pols)

    for pol in I.groebner_basis():
        try:
            univariate_pol = pol.univariate_polynomial()
        except Exception:
            continue

        roots = univariate_pol.small_roots(X=2^256, epsilon=0.05)

        for root in roots:
            yield int(root).to_bytes(1024, 'big').strip(b'\x00')


def main() -> None:
    if IP is None:
        raise Exception('pass ip as 1st argument')

    if FLAG_ID is None:
        raise Exception('pass flag_id as 2nd argument')

    # FLAG_ID: 'username|ciphertext_id'
    username, ciphertext_id = FLAG_ID.split('|')

    client = Client(IP, PORT)

    keyspace = client.get_keyspace(username)
    if keyspace is None:
        raise Exception('failed to get keyspace')

    ciphertext = client.get_ciphertext(ciphertext_id)
    if ciphertext is None:
        raise Exception('failed to get ciphertext')

    for flag in attack(keyspace, ciphertext):
        print(flag)


if __name__ == '__main__':
    main()
```

## Patch

Just change `bits` from 1024 to 512. Then $N \approx 1024 \text{ bits}$ and $m^n > N$.

Example patch: 

```diff
diff --git a/services/solaris/src/Controllers/Utils.php b/services/solaris/src/Controllers/Utils.php
index 96b771f0..cec14b9c 100644
--- a/services/solaris/src/Controllers/Utils.php
+++ b/services/solaris/src/Controllers/Utils.php
@@ -41,7 +41,7 @@ function validate_id(string $id): void
 
 function generate_key(): Key
 {
-    $parameters = Parameters::generate(1024, 2, 6, 4);
+    $parameters = Parameters::generate(512, 2, 6, 4);
 
     return Key::generate($parameters);
 }
```
