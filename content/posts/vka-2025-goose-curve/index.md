+++
title = 'VKACTF 2025 — Гусиные Кривые'
date = 2025-06-08T17:17:28+03:00
tags = ['ctf', 'writeup', 'crypto']
toc = true
tldr = 'bebrus'
+++

## Overview

We're given the following C++ code. Since the main language of VKACTF is Russian, there are many Russian texts among the code:

```cpp
#include <iostream>
#include <fstream>
#include <set>
#include <string>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>

using namespace CryptoPP;
using namespace std;

Integer NextPrime(const Integer& n) {
    Integer p = n;
    if (p % 2 == 0) p++;
    
    while (!IsPrime(p)) {
        p += 2;
    }
    return p;
}

Integer Tonnelli_Shanks(const Integer& a, const Integer& p) {
    if (Jacobi(a, p) != 1) return 0;
    if (a == 0) return 0;
    if (p == 2) return 0;
    
    if (p % 4 == 3) {
        return a_exp_b_mod_c(a, (p + 1) / 4, p);
    }
    
    Integer s = p - 1;
    int e = 0;
    while (s % 2 == 0) {
        s /= 2;
        e++;
    }
    
    Integer n = 2;
    while (Jacobi(n, p) != -1) {
        n++;
    }
    
    Integer x = a_exp_b_mod_c(a, (s + 1) / 2, p);
    Integer b = a_exp_b_mod_c(a, s, p);
    Integer g = a_exp_b_mod_c(n, s, p);
    int r = e;
    
    while (true) {
        Integer t = b;
        int m = 0;
        for (; m < r; m++) {
            if (t == 1) break;
            t = a_exp_b_mod_c(t, 2, p);
        }
        if (m == 0) return x;
        
        Integer gs = a_exp_b_mod_c(g, Integer::Power2(r - m - 1), p);
        g = (gs * gs) % p;
        x = (x * gs) % p;
        b = (b * g) % p;
        r = m;
    }
}

class EllipticCurve {
public:
    Integer p, a, b;
    
    EllipticCurve(const Integer& p, const Integer& a, const Integer& b) 
        : p(p), a(a), b(b) {
        if (!check_curve()) {
            throw runtime_error("Заяц – Гусь! Кривая - Некривая!");
        }
    }
    
    bool check_curve() const {
        Integer d = -16 * (4*a*a*a + 27*b*b);
        return (d % p) != 0;
    }
    
    Integer lift_x(const Integer& px) const {
        Integer y2 = (a_exp_b_mod_c(px, 3, p) + a*px + b) % p;
        Integer py = Tonnelli_Shanks(y2, p);
        if (py == 0) {
            throw runtime_error("Точка не пренадлежит кривой!");
        }
        return py;
    }
};

int main() {
    AutoSeededRandomPool prng;
    
    ifstream flag_file("flag.txt", ios::binary);
    if (!flag_file) {
        cerr << "Флю… флю… флюгегехайм… Стоп-слово! Стоп-слово!" << endl;
        return 1;
    }
    
    string flag_str((istreambuf_iterator<char>(flag_file)), istreambuf_iterator<char>());
    Integer flag(reinterpret_cast<const byte*>(flag_str.data()), flag_str.size());
    
    cout <<""<< endl;
    cout << "Я гусь! Я до тебя (додолблюсь!)" << endl;
    cout <<""<< endl;
    
    Integer p, a, b, fy;
    while (true) {
        p = Integer(prng, 762);  // Семьсот шестьдесят два... Семь сотен. Шесть десятков. И два.
        p = NextPrime(p);
        a = Integer(prng, 512);
        b = Integer(prng, 512);
        
        try {
            EllipticCurve E(p, a, b);
            fy = E.lift_x(flag);
            cout << "p = " << p << endl;
            cout << "Истинный y = " << fy << endl;
            break;
        } catch (...) {
            continue;
        }
    }
    
    set<Integer> checked;
    int count = 0;
    
    while (count < 3826) {       
        Integer x(prng, 2, p-1);
        
        if (checked.count(x) || x < Integer::Power2(512) || 
            (x > p ? x - p : p - x) < Integer::Power2(512)) {  
            cout << "Ломай меня полностью!" << endl;
            continue;
        }
        
        try {
            Integer e(prng, 55);
            cout << "e = " << e << endl;
            
            EllipticCurve E(p, a^e, b^e);
            Integer py = E.lift_x(x);
            
            checked.insert(x);
            cout << "x = " << x << endl;
            cout << "y = " << py << endl;
            count++;
        } catch (...) {
            cout << "Жгучие пироги! Кто ж думал-то, что вот так подряд техника будет сбоить?" << endl;
        }
        
        cout << "Продолжаем > ";
        string more;
        getline(cin, more);
        if (more == "Stop") {
            break;
        }
    }
    
    cout << "Я гусь! Я, пожалуй, (убегусь!)" << endl;
    return 0;
}
```

Despite the code is tricky, the math description of the challenge is simple. We could reformulate it as following.

Suppose we have a finite field $\mathbb{F}$ and an elliptic curve $\mathrm{E'}(\mathbb{F}, [a, b])$. Then we select a point $\mathrm{P}(x', y')$ where $x'$ is a flag. We know only $\mathbb{F}$ and $y'$, parameters $a$ and $b$ remain unknown.

Then we could repeatedly do the following operation:

1. generate a random 55-bit integer $e$
2. create another elliptic curve $\mathrm{E}(\mathbb{F}, [a\text{^}e, b\text{^}e])$
3. take a point $\mathrm{Q}(x, y)$ on the curve $\mathrm{E}$
4. print integer $e$ and point $\mathrm{Q}$

We need to recover original parameters $a$ and $b$ from the given pairs $(e_i, \mathrm{Q}_i)$.


## Description

From the definition of the elliptic curve we know that the point $\mathrm{Q}(x, y)$ lies on the curve $\mathrm{E}(\mathbb{F}, [a, b])$ when the following equation holds in $\mathbb{F}$:

$$y^2 \equiv x^3 + a \cdot x + b$$

In our case we're given an access to $n$ pairs of $(e_i, \mathbb{Q}_i)$, so we could construct the system of equations in $\mathbb{F}$:

$$\left\\{ \begin{aligned}
y_1^2 & \equiv x_1^3 + a \text{^} e_1 \cdot x_1 + b \text{^} e_1 \\\\
y_2^2 & \equiv x_2^3 + a \text{^} e_2 \cdot x_2 + b \text{^} e_2 \\\\
& \vdots \\\\
y_n^2 & \equiv x_n^3 + a \text{^} e_n \cdot x_n + b \text{^} e_n \\\\
\end{aligned} \right.$$

The only unknown variables are $a$ and $b$, so it's an overdetermined system of equations. But since numbers $e_i$ are relative big, it should be hard to solve. **Shouldn't it?**


## Linearization

The significant trick is a `^` operator. This is not exponentiation as it might seem at first glance, the `^` operator in C++ is XOR. Therefore the created curve $\mathrm{E}$ has the following definition:

$$\mathrm{E}(\mathbb{F}, [a \oplus e, b \oplus e])$$

And our system of equations transforms to:

$$\left\\{\begin{aligned}
y_1^2 & \equiv x_1^3 + (a \oplus e_1) \cdot x_1 + (b \oplus e_1) \\\\
y_2^2 & \equiv x_2^3 + (a \oplus e_2) \cdot x_2 + (b \oplus e_2) \\\\
& \vdots \\\\
y_n^2 & \equiv x_n^3 + (a \oplus e_n) \cdot x_n + (b \oplus e_n) \\\\
\end{aligned}\\right.$$

We could notice that the system is actually linear. Let's do the following:

1. set $a^{(H)}$ to $(512-55)$ most significant bits of $a$
2. set $b^{(H)}$ to $(512-55)$ most significant bits of $b$
3. set $(a_0^{(L)}, a_1^{(L)}, ..., a_{54}^{(L)})$ to 55 least significant bits of $a$
4. set $(b_0^{(L)}, b_1^{(L)}, ..., b_{54}^{(L)})$ to 55 least significant bits of $b$
5. and set $(e_{i,0}, e_{i,1}, ..., e_{i,54})$ to bits of $e$
5. then $a \oplus e_i = 2^{55} \cdot a^{(H)} + 2^{54} \cdot e_{i,54} \cdot a_{54}^{(L)} + 2^{53} \cdot e_{i,53} \cdot a_{53}^{(L)} + ... + 2^0 \cdot e_{i,0} \cdot a_0^{(L)}$
6. then $b \oplus e_i = 2^{55} \cdot b^{(H)} + 2^{54} \cdot e_{i,54} \cdot b_{54}^{(L)} + 2^{53} \cdot e_{i,53} \cdot b_{53}^{(L)} + ... + 2^0 \cdot e_{i,0} \cdot b_0^{(L)}$

Now we can rewrite the system as following:

$$\left\\{\begin{aligned}
y_1^2 - x_1^3 & \equiv \left( 2^{55} \cdot a^{(H)} + \sum_{j=0}^{54} 2^j \cdot e_{1,j} \cdot a_j^{(L)} \right) \cdot x_1 + \left( 2^{55} \cdot b^{(H)} + \sum_{j=0}^{54} 2^j \cdot e_{1,j} \cdot b_j^{(L)} \right) \\\\
y_2^2 - x_2^3 & \equiv \left( 2^{55} \cdot a^{(H)} + \sum_{j=0}^{54} 2^j \cdot e_{2,j} \cdot a_j^{(L)} \right) \cdot x_2 + \left( 2^{55} \cdot b^{(H)} + \sum_{j=0}^{54} 2^j \cdot e_{2,j} \cdot b_j^{(L)} \right) \\\\
& \vdots \\\\
y_n^2 - x_n^3 & \equiv \left( 2^{55} \cdot a^{(H)} + \sum_{j=0}^{54} 2^j \cdot e_{n,j} \cdot a_j^{(L)} \right) \cdot x_n + \left( 2^{55} \cdot b^{(H)} + \sum_{j=0}^{54} 2^j \cdot e_{n,j} \cdot b_j^{(L)} \right) \\\\
\end{aligned}\right.$$

It's obvious that the system became linear. Note that we know everything except $a^{(H)}, b^{(H)}, a_j^{(L)}, b_j^{(L)}$. So the system has $55 + 55 + 2 = 112$ unknowns. It's still solvable because we have access to $3826$ pairs of $(e_i, \mathrm{Q}_i)$. Therefore, we just need to solve matrix equation.

Suppose $T$ is a vector of left-hand sides:

$$T = \begin{pmatrix}
y_1^2 - x_1^3 \\\\
y_2^2 - x_2^3 \\\\
\vdots \\\\
y_n^2 - x_n^3 \\\\
\end{pmatrix}$$

And $M$ is a matrix defined as follows:

$$M = \begin{pmatrix}
2^{55} \cdot x_1 & 2^{54} \cdot e_{1,54} \cdot x_1 & ... & 2^0 \cdot e_{1,0} \cdot x_1 & 2^{55} & 2^{54} \cdot e_{1,54} & 2^{53} \cdot e_{1,53} & ... & 2^0 \cdot e_{1,0} \\\\
2^{55} \cdot x_2 & 2^{54} \cdot e_{2,54} \cdot x_2 & ... & 2^0 \cdot e_{2,0} \cdot x_2 & 2^{55} & 2^{54} \cdot e_{2,54} & 2^{53} \cdot e_{2,53} & ... & 2^0 \cdot e_{2,0} \\\\
\vdots & \vdots & \ddots & \vdots & \vdots & \vdots & \vdots & \ddots & \vdots \\\\
2^{55} \cdot x_n & 2^{54} \cdot e_{n,54} \cdot x_n & ... & 2^0 \cdot e_{n,0} \cdot x_n & 2^{55} & 2^{54} \cdot e_{n,54} & 2^{53} \cdot e_{n,53} & ... & 2^0 \cdot e_{n,0} \\\\
\end{pmatrix} $$

And $X$ is a vector of unknowns:

$$X = \begin{pmatrix}
a^{(H)} \\\\
a_{54}^{(L)} \\\\
\vdots \\\\
a_0^{(L)} \\\\
b^{(H)} \\\\
b_{54}^{(L)} \\\\
\vdots \\\\
b_{0}^{(L)} \\\\
\end{pmatrix}$$

Then we have to solve the following matrix equation in $\mathbb{F}$:

$$MX = T$$


## Implementation

Let's use sagemath. 

We will skip the client implementation, suppose we already have the following values:

1. `p` is an order of finite field $\mathbb{F}$
2. `y_flag` is a $y'$-coordinate of a flag point $\mathrm{P}(x', y')$
3. `es` and `Qs` are the given arrays of $e_i$ and $\mathrm{Q}_i$ respectively

Here is a function to recover the parameters $a$ and $b$:

```sage
def recover_parameters(p, es, Qs):
    F = GF(p)
    n = len(es)

    T = vector(F, [(y^2 - x^3) for x, y in Qs])

    M = Matrix(F, n, 112)

    for i in range(n):
        e = es[i]
        x, y = Qs[i]

        e_bits = [(e >> i) & 1 for i in range(55)]

        M[i, 0] = 2^55 * x
        
        for j in range(55):
            M[i, 1 + j] = 2^j * e_bits[j] * x

        M[i, 1 + 55] = 2^55

        for j in range(55):
            M[i, 1 + 55 + 1 + j] = 2^j * e_bits[j]
    
    X = M.solve_right(T)

    a_H = X[0]
    b_H = X[1 + 55]

    a_L, b_L = 0, 0

    for j in range(55):
        a_bit = X[1 + j]
        b_bit = X[1 + 55 + 1 + j]

        a_L += (int(a_bit) & 1) * 2^j
        b_L += (int(b_bit) & 1) * 2^j

    a = 2^55 * a_H + (int(a_L) & (2^55))
    b = 2^55 * b_H + (int(b_L) & (2^55))

    return a, b
```

And then we just recover $x'$ coordinate of $\mathrm{P}$:

```sage
def reconstruct_flag(p, a, b, y_flag):
    F = GF(p)
    R.<X> = PolynomialRing(F)

    poly = (y_flag^2) - (X^3 + a*X + b)

    for x_flag, _ in poly.roots():
        flag = int(x_flag).to_bytes(762 // 8, 'big')

        return flag
```


## Flag

```
vka{goose_swearer_vs_cryptor}
```


## Conclusion

The [indended solution](https://github.com/Red-Cadets/VKACTF-2025/blob/main/categories/crypto/cry-medium-ecc/solution/writeup.md) involves building a lattice and solving CVP, so the solution above is unintended. But anyway I've enjoyed the challenge, many thanks to the organizing team [Red Cadets](https://github.com/Red-Cadets).
