+++
title = 'SECCON CTF 14 Quals — Last Flight'
date = 2025-12-14T23:37:00+03:00
tags = ['ctf', 'writeup', 'crypto']
toc = true
tldr = 'abusing DFS to find a path in isogeny graph'
+++

## Description

> I got split up from them. It is the final chance. Can you find a special flight?
> 
> **Please solve it locally first before trying it on the server. **
> 
> _author:kanon_

## Overview

We're given the following source code:

```python
from Crypto.Util.number import *
from random import randint
import os

p = 4718527636420634963510517639104032245020751875124852984607896548322460032828353
j = 4667843869135885176787716797518107956781705418815411062878894329223922615150642

flag = os.getenv("FLAG", "SECCON{test_flag}")


def interstellar_flight(j, flight_plans=None):
    planet = EllipticCurve(GF(p), j=j)
    visited_planets = []
    if flight_plans == None:
        flight_plans = [randint(0, 2) for _ in range(160)]

    for flight_plan in flight_plans:
        flight = planet.isogenies_prime_degree(2)[flight_plan]
        if len(visited_planets) > 1:
            if flight.codomain().j_invariant() == visited_planets[-2]:
                continue
        planet = flight.codomain()
        visited_planets.append(planet.j_invariant())
    return visited_planets[-1]


print("Currently in interstellar flight...")

vulcan = interstellar_flight(j)
bell = interstellar_flight(j)

print(f"vulcan's planet is here : {vulcan}")
print(f"bell's planet is here : {bell}")


final_flight_plans = list(map(int, input("Master, please input the flight plans > ").split(", ")))

if interstellar_flight(vulcan, final_flight_plans) == bell:
    print(f"FIND THE BELL'S SIGNAL!!! SIGNAL SAY: {flag}")
else:
    print("LOST THE SIGNAL...")
```

The challenge involves work with elliptic curves and isogenies. In terms of isogenies a j-invariant is a value that describes the isomorphism class of elliptic curves, so all curves within the same j-invariant are isomorphic. Therefore in order to find an isogeny we could take arbitrary curve with the desired j-invariant.

We're given the initial j-invariant `j` and the `interstellar_flight()` function. The function moves the corresponding curve between the random isogenies and outputs the j-invariant of the resulting curve.

We need to find a sequence of isogenies that transforms `vulcan` curve in `bell` curve.

## Investigation

Since we're working with isogenies, we need to check the complex multiplication (CM) property of the given curve. Let's look at the descriminant:

```
sage: E = EllipticCurve(GF(p), j = j)
sage: t = E.trace_of_frobenius()
sage: D = t^2 - 4*p
sage: factor(D)
-1 * 2^256 * 163
```

We observed that $D = f^2 \cdot D_K$, where

- $D_K = -163$ is a fundamental discriminant, which confirms that the curve is in CM class
- $f = 2^{128}$ is a conductor, which describes the depth of the isogeny graph

The CM component is isomorphic to a Cayley graph, where nodes are j-invariants (elliptic curves) and edges are isogenies. Basically the graph is a binary tree with depth $128$ (according to $f$). Since we're working with isogenies of degree $2$, on the each step we've got at most $3$ isogenies, where $1$ isogeny is a backtrack (move to the previous curve). The leafs have only one backtrack isogeny.

Note that the generated in challenge path contains $160$ egdes, but actually $\sim \dfrac{1}{3}$ edges are rejected, because the code has backtracking check. So the actual path length is $\sim 105 < 128$.

It means the following:

- we're given the graph of elliptic curves connected by isogenies
- we need to find a path between nodes `vulcan` and `bell`

Since the graph is a tree, the goal is straightforward:

1. find the least common ancestor (LCA) of `vulcan` and `bell`, let's call it `lca` (`j` or other closer curve)
2. find an ascending path `vulcan_path` from `vulcan` to `lca`
3. find an ascending path `bell_path` from `bell` to `lca`
4. inverse `bell_path` (make it descending) and output the concatenation of paths

The ascending path should contain only backtracking isogenies.

## Solution

It seems that we don't need to find any isogeny-related attack and focus only on a graph problem.

The main question is the following: how to find a path in the binary tree between the two given nodes? Well-known $O(n)$ algorithms such as BFS or RMQ-based LCA fails because the graph contains $\sim 2^{128}$ nodes. Luckily we don't need to find arbitrary path, only the ascending path.

Suppose we know the height of each node:

- leaf has height $0$
- root (`j` curve) has height $128$
- `vulcan` and `bell` curves have height $\sim 23$

When we're moving from a node to the root we need to check neighbours heights. If the height of a neighbour is greater than the current height, then the node is closer to the root, otherwise it's closer to the leaf. Therefore we need to construct the path with the increasing heights.

But there is another problem: how to effectively calculate the height of a node? Common ways such as BFS works in $O(n)$, so at the height $h$ we need to traverse over $2^h$ nodes. I've found a probabilistic approach.

Suppose we have a leaf-finding procedure, based on DFS, that traverses the graph from the given node and terminates on the node with exactly one neighbour. On the each step this procedure selects a random neighbour in order to provide a kind of random walk. When we run the procedure _enough_ times from the given node, we _quite likely_ (I don't want to estimate the probability) will find the shortest path to the leaf. We will use this heuristic to estimate the height of the node.

The main idea of the algorithm:

```python
def ascend(node, root, accuracy):
    current = node
    current_height = min(dfs(node) for _ in range(accuracy))

    path = [current]

    while current != root:
        for neighbor in neighbors(current):
            height = dfs(neighbor)

            if height == current_height + 1:
                path.append(neighbor)

                current = neighbor
                current_height = height 

                break

    return path
```

At first we need to compute paths to the known common root `j`:

```python
vulcan_path = ascend(vulcan, j)
bell_path = ascend(bell, j)
```

Then we need to trim the common prefix, inverse `bell_path` and output the result.

## Optimization

Since we're abusing DFS on each step, we need to call `neighbors()` function many times on different nodes. When it's based on elliptic curve cryptography, it computes too slow:

```python
isogeny = curve.isogenies_prime_degree(2)[idx]
neighbor = isogeny.codomain().j_invariant()
```

We could speed it up using the modular polynomial $\Phi_2(X, Y)$. When two j-invariants connected by isogeny of degree 2, the following holds:

$$\Phi_2(j_1, j_2) = 0$$

The polynomial is defined as follows:

```
sage: from sage.modular.ssmod.ssmod import Phi_polys
sage: X, Y = var('X', 'Y')
sage: Phi_2 = Phi_polys(2, X, Y)
sage: Phi_2
(X^3 + Y^3) - X^2*Y^2 + 1488*(X^2*Y + X*Y^2) - 162000*(X^2 + Y^2) + 40773375*X*Y + 8748000000*(X + Y) - 157464000000000
```

Therefore we can calculate the neighbors the faster way:

```python
P.<X> = PolynomialRing(F)

def neighbors(j):
    poly = Phi_polys(2, X, j)
    roots = poly.roots(multiplicities = False)

    return sorted(roots)
```

## Flag

```
> nc last-flight.seccon.games 5000
-e Install hashcash on Ubuntu with `sudo apt install hashcash`. For other distros, see http://www.hashcash.org/.

hashcash -mb28 PgaAzJIWgyoKGPX7
hashcash token:
1:28:251215:pgaazjiwgyokgpx7::cimil9euzQd4QtBy:CRjKb
[+] Correct
Currently in interstellar flight...
vulcan's planet is here : 2126230660136496101201945892398300997097213416663280684436417497015666603400966
bell's planet is here : 2674639099801691865465226271579999293879873473739120740692636897543334067404071
Master, please input the flight plans > 2, 2, 1, 2, 1, 2, 0, 1, 2, 2, 0, 1, 1, 0, 0, 0, 0, 2, 0, 2, 0, 1, 1, 2, 1, 2, 2, 0, 2, 2, 1, 1, 0, 0, 0, 1, 2, 2, 0, 1, 0, 1, 0, 2, 1, 2, 1, 0, 1, 1, 0, 2, 1, 2, 2, 1, 2, 1, 1, 2, 0, 0, 0, 2, 2, 1, 1, 1, 1, 2, 2, 2, 0, 2, 2, 1, 0, 0, 1, 1, 1, 1, 0, 2, 2, 1, 2, 2, 2, 1, 2, 1, 1, 0, 1, 1, 2, 0, 0, 2, 2, 2, 2, 2, 1, 0, 1, 2, 0, 1, 2, 2, 1, 2, 1, 1, 2, 2, 0, 0, 2, 1, 0, 1, 2, 1, 0, 2, 2, 1, 2, 2, 2, 2, 0, 1, 0, 0, 1, 1, 1, 0, 1, 2, 2, 2, 1, 2, 2, 1, 2, 2, 2, 1, 2, 0, 1, 2, 1, 1, 2, 1, 2, 2, 1, 2, 1, 2, 0, 1, 2, 2, 2, 0, 0, 1, 2, 2, 1, 2, 2, 1, 0, 0, 2, 2, 2, 1, 0, 2, 1, 2, 0, 0, 2, 0, 0, 1, 2, 2, 2, 2, 0, 1, 1, 1, 0, 2, 1, 2, 2, 0, 2, 2, 2, 1, 1, 2, 2, 2
FIND THE BELL'S SIGNAL!!! SIGNAL SAY: SECCON{You_have_made_your_wish_so_you_have_got_to_make_it_true}
```
