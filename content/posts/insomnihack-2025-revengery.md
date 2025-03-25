+++
title = "Insomni'hack 2025 - revengery"
date = 2025-03-17T19:14:33+03:00
tags = ['web3', 'crypto']
toc = true
+++

_TL;DR: A web3 challenge written in Solidity. The main goal is to takeover the ownership of the vulnerable contract using the ECDSA signature forgery._

## Overview

> **revengery**
> 
> Maybe you recovered but now I want my revenge!

This is a web3 challenge written in Solidity. We're given the following contract:

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import "@openzeppelin/access/Ownable.sol";
import "@openzeppelin/utils/cryptography/ECDSA.sol";

contract Revengery is Ownable{
    bool public solved;
    address public immutable signer_addr;

    constructor() Ownable(msg.sender) {
        solved = false;
        // signer_pubkey = 039e1b969068ba94e6c0f80a62c48a2406412dcb7043b9aa360b788097e7e9fd65
        signer_addr = 0x8E2227b11dd10a991b3CB63d37276daC4E4b9417;
    }

    /**
     * Only the owner can solve the challenge ;)
     */
    function solve() external onlyOwner{
        solved = true;
    }

    /**
     * Is the challenge solved ?
     */
    function isSolved() public view returns (bool) {
        return solved;
    }

    /**
     * @dev Change owner
     * @param signature signature of the hash
     * @param hash hash of the message authenticating the new owner
     * @param newOwner address of the new owner
     */
    function changeOwner(bytes memory signature, bytes32 hash, address newOwner) public {
        require(newOwner != address(0), "New owner should not be the zero address");
        require(hash != bytes32(0), "Not this time");
        address _signer = ECDSA.recover(hash, signature);
        require(signer_addr == _signer, "New owner should have been authenticated by the signer");
        _transferOwnership(newOwner);
    }
}
```

In order to get the flag we need to make the method `isSolved()` return true.

## Explanation

We see that Revengery is [Ownable](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol) contract. It means that the deployed contract stores the _owner_ address internally and provides the `onlyOwner` modifier. All methods tagged with this modifier perform an ownership check before the execution, basically they compare the _caller_ address with the saved _owner_ address. The initial owner is the challenge runner.

In our case the `onlyOwner` method is `solve()`, which is our target, so in order to execute it we need to transfer the ownership of the deployed contract to our address.

The contract provides a helpful method `changeOwner()` that calls `_transferOwnership()` internally.

## ECDSA recover

The ECDSA recover process does the following:

1. take the **hash** of the signed message and its **signature**
2. recover the public key of **signer**
3. verify the **signature** using the **signer**'s public key
4. return the **signer**'s address if the **signature** is correct

In this challenge we're able to send arbitrary **hash** and **signature** values to `ECDSA.recover()` method. We need to craft such parameters that returns the `signer_addr` address:

```
signer_addr = 0x8E2227b11dd10a991b3CB63d37276daC4E4b9417
```

Note that in Ethereum the address value is generated from the public key. And we're given the public key of the `signer_addr`:

```
signer_pubkey = 039e1b969068ba94e6c0f80a62c48a2406412dcb7043b9aa360b788097e7e9fd65
```

So our goal is to craft a forged **signature** that could be verified by `signer_pubkey`. We need to investigate what the verifying process looks like.

## ECDSA library

At first look at the [ECDSA](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol) library. We can find the target functions:

```solidity
function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
    (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, signature);
    _throwError(error, errorArg);
    return recovered;
}

function tryRecover(
    bytes32 hash,
    bytes memory signature
) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
    if (signature.length == 65) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        assembly ("memory-safe") {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return tryRecover(hash, v, r, s);
    } else {
        return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));
    }
}

function tryRecover(
    bytes32 hash,
    uint8 v,
    bytes32 r,
    bytes32 s
) internal pure returns (address recovered, RecoverError err, bytes32 errArg) {
    // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
    // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
    // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
    // signatures from current libraries generate a unique signature with an s-value in the lower half order.
    //
    // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
    // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
    // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
    // these malleable signatures as well.
    if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
        return (address(0), RecoverError.InvalidSignatureS, s);
    }

    // If the signature is valid (and not malleable), return the signer address
    address signer = ecrecover(hash, v, r, s);
    if (signer == address(0)) {
        return (address(0), RecoverError.InvalidSignature, bytes32(0));
    }

    return (signer, RecoverError.NoError, bytes32(0));
}
```

Note that the **signature** value splits into the three parts:

- $v$ — a number 27 or 28, used to recover EC point from $x$-coordinate
- $r$, $s$ — ECDSA signature parameters

Then the resulting values $(hash, v, r, s)$ are passed to `ecrecover()`.

## EVM source code

Let's look at the EVM source code in order to find how `ecrecover()` is implemented:

- [secp256k1/k256.rs](https://github.com/bluealloy/revm/blob/main/crates/precompile/src/secp256k1/k256.rs)

```rust
pub fn ecrecover(sig: &B512, mut recid: u8, msg: &B256) -> Result<B256, Error> {
    // parse signature
    let mut sig = Signature::from_slice(sig.as_slice())?;

    // normalize signature and flip recovery id if needed.
    if let Some(sig_normalized) = sig.normalize_s() {
        sig = sig_normalized;
        recid ^= 1;
    }
    let recid = RecoveryId::from_byte(recid).expect("recovery ID is valid");

    // recover key
    let recovered_key = VerifyingKey::recover_from_prehash(&msg[..], &sig, recid)?;
    // hash it
    let mut hash = keccak256(
        &recovered_key
            .to_encoded_point(/* compress = */ false)
            .as_bytes()[1..],
    );

    // truncate to 20 bytes
    hash[..12].fill(0);
    Ok(hash)
}
```

Now let's look at the ECDSA library source code:

- [ecdsa/recovery.rs](https://docs.rs/ecdsa/0.16.9/src/ecdsa/recovery.rs.html)

```rust
/// Recover a [`VerifyingKey`] from the given `prehash` of a message, the
/// signature over that prehashed message, and a [`RecoveryId`].

#[allow(non_snake_case)]
pub fn recover_from_prehash(
    prehash: &[u8],
    signature: &Signature<C>,
    recovery_id: RecoveryId,
) -> Result<Self> {
    let (r, s) = signature.split_scalars();
    let z = <Scalar<C> as Reduce<C::Uint>>::reduce_bytes(&bits2field::<C>(prehash)?);

    let mut r_bytes = r.to_repr();
    if recovery_id.is_x_reduced() {
        match Option::<C::Uint>::from(
            C::Uint::decode_field_bytes(&r_bytes).checked_add(&C::ORDER),
        ) {
            Some(restored) => r_bytes = restored.encode_field_bytes(),
            // No reduction should happen here if r was reduced
            None => return Err(Error::new()),
        };
    }
    let R = AffinePoint::<C>::decompress(&r_bytes, u8::from(recovery_id.is_y_odd()).into());

    if R.is_none().into() {
        return Err(Error::new());
    }

    let R = ProjectivePoint::<C>::from(R.unwrap());
    let r_inv = *r.invert();
    let u1 = -(r_inv * z);
    let u2 = r_inv * *s;
    let pk = ProjectivePoint::<C>::lincomb(&ProjectivePoint::<C>::generator(), &u1, &R, &u2);
    let vk = Self::from_affine(pk.into())?;

    // Ensure signature verifies with the recovered key
    vk.verify_prehash(prehash, signature)?;

    Ok(vk)
}
```

Note that `prehash` is our **hash** value and `recovery_id` is derived from $v$ number. We won't go deeply into its logic, just remember that we can control $y$ coordinate of EC point changing the $v$ value.

Finally look at `verify_prehashed()` function that's used internally in `VerifyingKey.verify_prehash()`:

- [ecdsa/hazmat.rs](https://docs.rs/ecdsa/latest/src/ecdsa/hazmat.rs.html)

```rust
/// Verify the prehashed message against the provided ECDSA signature.
///
/// Accepts the following arguments:
///
/// - `q`: public key with which to verify the signature.
/// - `z`: message digest to be verified. MUST BE OUTPUT OF A
///        CRYPTOGRAPHICALLY SECURE DIGEST ALGORITHM!!!
/// - `sig`: signature to be verified against the key and message.
#[cfg(feature = "arithmetic")]
pub fn verify_prehashed<C>(
    q: &ProjectivePoint<C>,
    z: &FieldBytes<C>,
    sig: &Signature<C>,
) -> Result<()>
where
    C: PrimeCurve + CurveArithmetic,
    SignatureSize<C>: ArrayLength<u8>,
{
    let z = Scalar::<C>::reduce_bytes(z);
    let (r, s) = sig.split_scalars();
    let s_inv = *s.invert_vartime();
    let u1 = z * s_inv;
    let u2 = *r * s_inv;
    let x = ProjectivePoint::<C>::lincomb(&ProjectivePoint::<C>::generator(), &u1, q, &u2)
        .to_affine()
        .x();

    if *r == Scalar::<C>::reduce_bytes(&x) {
        Ok(())
    } else {
        Err(Error::new())
    }
}
```

Note that $z$ is our **hash** value converted to number, and $q$ is a public key point. Now we can analyze the cryptographic part.

## Cryptanalysis

Suppose we're working in SECP256k1 curve which has a generator $G$. The ECSDA recovery algorithm is following:

1. $R = curve.lift\\_x(r)$ — lift point $R$ from $x = r$ coordinate
2. $u_1 = -(r^{-1} \cdot z)$ \
   $u_2 = r^{-1} \cdot s$
3. $Q = u_1 \cdot G + u_2 \cdot R$ — public key of the signer

The resulting point $Q$ should match the `signer_pubkey` value from the challenge. But, moreover, this $Q$ point should verify the message signature. Let's look at the ECDSA verifying algorithm:

1. $u_3 = z \cdot s^{-1}$ \
   $u_4 = r \cdot s^{-1}$
2. $x = (u_3 \cdot G + u_4 \cdot Q).x$
3. assert $x == r$

So we need to input such $z$, $r$ and $s$ that the both checks are passed.

## Exploitation

The obvious problem here is a linear combination with the $G$ point. When $u_1 \neq 0$ and $u_3 \neq 0$ the solution would involve the [discrete logarithm](https://en.wikipedia.org/wiki/Discrete_logarithm) (ECDLP) computation, and that would be impossible for the SECP256k1 curve.

We would try to elimitate the $G$ term passing $u_1 = u_3 = 0$. Since they both have the multiplier $z$ we may pass $z = 0$. But such $z$ value is forbidden in the challenge contract:

```solidity
require(hash != bytes32(0), "Not this time");
```

We could pass SECP256k1 group order instead:

```
> SECP256k1.order()
0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

Then we get the following:

- $R = curve.lift\\_x(r)$
- $u_1 = 0$ \
  $u_2 = r^{-1} \cdot s$
- $Q = u_2 \cdot R = (r^{-1} \cdot s) \cdot R$
- $u_3 = 0$ \
  $u_4 = r \cdot s^{-1}$
- $x = (u_4 \cdot Q).x = ((r \cdot s^{-1}) \cdot Q).x$
- assert $x == r$

Since $Q$ should be equal to $R$ we may set $s = r$ and obtain $r^{-1} \cdot s = 1$, so:

- $R = curve.lift\\_x(r)$
- $Q = (r^{-1} \cdot r) \cdot R = R$
- $x = ((r \cdot r^{-1}) \cdot Q).x = Q.x$
- assert $x == r$

Finally all checks are passed.

## Solution

So, combining results together, we get:

- $hash = z = SECP256k1.order()$

```
hash = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
```

- $r = s = signer\\_pubkey.x$

```
r = s = 0x9e1b969068ba94e6c0f80a62c48a2406412dcb7043b9aa360b788097e7e9fd65
```

- $v = 28$ in order to recover the desired $y$ coordinate of EC point

But let's look at `tryRecover()` again. We can't pass such $s$ because it volatiles the constraint:

```solidity
if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
    return (address(0), RecoverError.InvalidSignatureS, s);
}
```

Luckily the solution is described in the comment above:

```
// the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
// signatures from current libraries generate a unique signature with an s-value in the lower half order.
//
// If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
// with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
// vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
// these malleable signatures as well.
```

So just do the following:

- $s = SECP256k1.order() - s$

```
s = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141-0x9e1b969068ba94e6c0f80a62c48a2406412dcb7043b9aa360b788097e7e9fd65 =
  = 0x61e4696f97456b193f07f59d3b75dbf8798111766b8ef605b459ddf4e84c43dc
```

- $v = 27$

## Final exploit

```solidity
challenge.changeOwner(
    abi.encodePacked(
        bytes32(0x9e1b969068ba94e6c0f80a62c48a2406412dcb7043b9aa360b788097e7e9fd65),
        bytes32(0x61e4696f97456b193f07f59d3b75dbf8798111766b8ef605b459ddf4e84c43dc),
        uint8(27)
    ),
    bytes32(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141),
    player
);
```

## Conclusion

The challenge itself is almost the same as the similar challenge from the quals:

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

import "@openzeppelin/access/Ownable.sol";

contract Recovery is Ownable{
    bool public solved;

    constructor() Ownable(msg.sender) {
        solved = false;
    }

    /**
     * Only the owner can solve the challenge.
     */
    function solve() external onlyOwner{
        solved = true;
    }

    /**
     * Is the challenge solved ?
     */
    function isSolved() public returns (bool) {
        return solved;
    }

    /**
     * @dev Change owner
     * @param v signature of the hash
     * @param r signature of the hash
     * @param s signature of the hash
     * @param hash hash of the message authenticating the new owner
     * @param newOwner address of the new owner
     */
    function changeOwner(uint8 v, bytes32 r, bytes32 s, bytes32 hash, address newOwner) public {
        require(newOwner != address(0), "New owner should not be the zero address");
        address signer = ecrecover(hash, v, r, s);
        require(signer == owner(), "New owner should have been authenticated");
        _transferOwnership(newOwner);
    }
}
```

The only difference is the additional check for $hash \neq 0$, which could be easily bypassed by SECP256k1's order.

The challenge was solved by **renbou**, **defkit** and **keltecc** on behalf of the [PokemonCollection](https://ctftime.org/team/215658/) team.
