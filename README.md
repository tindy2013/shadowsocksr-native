# ShadowsocksR-native

## Index

- [Intro](#intro)
- [Features](#features)
- [Protocols & obfuscators](#protocols--obfuscators)
- [Installation](#installation)
- [Sample configure file](#sample-configure-file)
- [cmake](#cmake)


## Intro

**ShadowsocksR-native** is a lightweight secured SOCKS5 proxy for embedded devices and low-end boxes.
It's derived from [Shadowsocks-libev](http://shadowsocks.org).

It is a port of [ShadowsocksR](https://github.com/breakwa11)
created by [@breakwa11](https://github.com/breakwa11), 
which is maintained by [@ssrlive](https://github.com/ssrlive).

Current version: 0.4 | [Changelog](debian/changelog)

## Features

ShadowsocksR-native is written in pure C and only depends on
[libuv](https://github.com/libuv/libuv) ,
[mbedTLS](https://github.com/ARMmbed/mbedtls) , 
[libsodium](https://github.com/jedisct1/libsodium) and
[json-c](https://github.com/json-c/json-c).

In normal usage, the memory footprint is about 600KB and the CPU utilization is
no more than 5% on a low-end router (Buffalo WHR-G300N V2 with a 400MHz MIPS CPU,
32MB memory and 4MB flash).

For a full list of feature comparison between different versions of shadowsocks,
refer to the [Wiki page](https://github.com/shadowsocksr-live/shadowsocksr-native/wiki/).

## Protocols & obfuscators

| Protocols | obfuscators | 
| --------- | ----------- | 
| origin | plain |
| auth_sha1_v4 | http_simple |
| auth_aes128_sha1 | http_post |
| auth_aes128_md5 | http_mix |
| auth_chain_a | tls1.2_ticket_auth |
| auth_chain_b |    |
| auth_chain_c/d/e/f |    |

progress of data flow
```
+-----------------------------------------------------------------------------+
|                +--------------------------------------------------------+   |
|                |               +------------------------------------+   |   |
|                |               |            +-------------------+   |   |   |
|  obfuscator    |   encryptor   |  protocol  |     user data     |   |   |   |
|   |            |       |       |      |     +-------------------+   |   |   |
|   |            |       |       +------+-----------------------------+   |   |
|   |            +-------+--------------+---------------------------------+   |
+---+--------------------+--------------+-------------------------------------+
    |                    |              |                                            
    +-- server_encode    +-- encrypt    +-- server_pre_encrypt       <<<=== user data
    |                    |              |                                            
    +-- server_decode    +-- decrypt    +-- server_post_decrypt      ===>>> user data
```

## Installation

### Distribution-specific guide

- [Debian & Ubuntu](#debian--ubuntu)
    + [Install from repository](#debian--ubuntu)
- [Fedora & RHEL](#fedora--rhel)
    + [Install from repository](#centos)
- [CentOS](#centos)
    + [Install from repository](#centos)
- [OS X](#os-x)
- [Windows](#windows)

* * *

### Debian & Ubuntu

For Unix-like systems, especially Debian-based systems,
e.g. Ubuntu, Debian or Linux Mint, you can build the binary like this:

```bash
# Debian / Ubuntu
sudo su                       # using root account
apt-get install --no-install-recommends build-essential autoconf libtool asciidoc xmlto -y
apt-get install git gcc g++ cmake automake -y
apt-get -f install
apt-get update
apt-get upgrade

cd /                          # switch to root directory
git clone https://github.com/ShadowsocksR-Live/shadowsocksr-native.git
mv shadowsocksr-native ssr-n  # rename shadowsocksr-native to ssr-n
cd ssr-n                      # enter ssr-n directory. 
git submodule update --init
git submodule foreach -q 'git checkout $(git config -f $toplevel/.gitmodules submodule.$name.branch || echo master)'

# build ShadowsocksR-native
cmake CMakeLists.txt && make
```

### CentOS

CentOS 7 only. we don't support CentOS 6.x, it's too old.

Before build `ssr-Native`, we must install `cmake` 3.x first. following [this](#cmake) 

```bash
# CentOS / Fedora / RHEL
sudo su
yum install wget git gcc gcc-c++ autoconf automake libtool make asciidoc xmlto -y
cd /
git clone https://github.com/ShadowsocksR-Live/shadowsocksr-native.git
mv shadowsocksr-native ssr-n
cd ssr-n
git submodule update --init
cmake . && make
```

### OS X

For OS X, use [Homebrew](http://brew.sh) to install or build.

Install Homebrew:

```bash

```

### Windows

For Windows, chekout the project using the following commands then open win32/ssr-native.sln with Visual Studio 2010. Enjoy it!

```bash
git clone https://github.com/ShadowsocksR-Live/shadowsocksr-native.git 
git submodule update --init
git submodule foreach -q 'git checkout $(git config -f $toplevel/.gitmodules submodule.$name.branch || echo master)'
```

## Usage

For a detailed and complete list of all supported arguments, you may refer to the
man pages of the applications, respectively.

```
    ssr-[client|local|server]

       [-c <config_file>]         The path to config file

       [-d]                       Run in background as a daemon.

       [-h]                       Show this help message.
```

## Sample configure file
config.json
```json
{
    "server": "123.45.67.89",
    "server_port": 443,
    "method": "aes-128-ctr",
    "password": "password",
    "protocol": "auth_aes128_md5",
    "protocol_param": "",
    "obfs": "tls1.2_ticket_auth",
    "obfs_param": "",
    "local_address": "0.0.0.0",
    "local_port": 1080,
    "udp": true,
    "timeout": 300
}
```


## cmake

In the CentOS 7, the cmake version is too old to work with ShadowsocksR-Native. 
So we must install it by ourselves.

```bash
sudo su
cd /
curl https://cmake.org/files/v3.11/cmake-3.11.4-Linux-x86_64.sh -o a.sh
sh a.sh  --prefix=/usr/ --exclude-subdir
rm -rf a.sh
cmake --version
```

It will spend about 30 minites. And the `cmake --version` command will output message likes:
```
cmake version 3.11.4
CMake suite maintained and supported by Kitware (kitware.com/cmake).
```
