
# PSI-GM

**PSI-GM** 是基于 [OpenMined/PSI v2.0.6](https://github.com/OpenMined/PSI/tree/v2.0.6) 的国密扩展版本，
在保持原有隐私集合求交协议（Private Set Intersection, PSI）框架不变的前提下，
引入了中国国家密码算法（SM 系列）支持，适配国内商用密码标准及相关合规场景。

---

## 🔍 项目简介

[OpenMined/PSI](https://github.com/OpenMined/PSI) 是一个开源的私有集合求交（PSI）框架，
可在不泄露参与方输入数据的情况下计算数据集交集。

**PSI-GM** 在此基础上将原使用的 ECC（如 `secp256r1`）与哈希算法（如 `SHA256`）替换为国密算法：

* 椭圆曲线公钥加密算法：**SM2**
* 哈希算法：**SM3**

从而实现全流程国密化 PSI 协议，支持在符合中国密码标准的环境中使用。



---



## 🔒 技术要点

* 替换 ECC 曲线为 **SM2**
* 哈希函数改为 **SM3**，保持相同接口签名
* 在协议层实现 SM2 公钥加密 + SM3 哈希结合的私有匹配流程
* 使用 **RFC 9380 Hash-to-Curve** 标准实现 SM2 曲线哈希映射

---

## 📚 参考标准

* [GM/T 0003-2012 SM2 椭圆曲线公钥密码算法](https://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002386.shtml)
* [GM/T 0004-2012 SM3 密码杂凑算法](https://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002388.shtml)
* [GM/T 0002-2012 SM4 分组密码算法](https://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002387.shtml)
* [RFC 9380 – Hashing to Elliptic Curves](https://datatracker.ietf.org/doc/html/rfc9380)

---

## 🧾 版本信息

| 项目     | 版本                                                                   |
| ------ | -------------------------------------------------------------------- |
| 上游项目   | [OpenMined/PSI v2.0.6](https://github.com/OpenMined/PSI/tree/v2.0.6) |
| 国密扩展作者 | CHENHE                                                                   |

---

## 📄 License

本项目沿用原 [OpenMined/PSI](https://github.com/OpenMined/PSI) 的 Apache License 2.0 许可协议。

---

## 🧠 相关项目

* [OpenMined/PSI](https://github.com/OpenMined/PSI)
* [BoringSSL-GM](https://github.com/HunterChan-SR/BoringSSL-GM)

---

# 原README:



![om-logo](https://github.com/OpenMined/design-assets/blob/master/logos/OM/horizontal-primary-trans.png)

[![CD](https://github.com/OpenMined/PSI/actions/workflows/CD.yml/badge.svg?event=release)](https://github.com/OpenMined/PSI/actions/workflows/CD.yml)
![License](https://img.shields.io/github/license/OpenMined/PSI)
![OpenCollective](https://img.shields.io/opencollective/all/openmined)

# PSI

Private Set Intersection protocol based on ECDH and Golomb Compressed Sets or
Bloom Filters.

## Protocol

The Private Set Intersection (PSI) protocol involves two parties, a client and a
server, each holding a dataset. The goal of the protocol is for the client to
determine the intersection between their dataset and the server's dataset,
without revealing any information about their respective datasets to each other.

The protocol proceeds as follows:

1. Setup (server)

The server encrypts all its elements `x` under a commutative encryption scheme,
computing `H(x)^s` where `s` is its secret key. The encrypted elements are then
inserted into a container and sent to the client in the form of a serialized
protobuf and resembles* the following:

```
[ H(x_1)^(s), H(x_2)^(s), ... , H(x_n)^(s) ]
```

2. Request (client)

The client encrypts all their elements `x` using the commutative encryption
scheme, computing `H(x)^c`, where `c` is its secret key. The client sends its
encrypted elements to the server along with a boolean flag,
`reveal_intersection`, indicating whether the client wants to learn the elements
in the intersection or only its size (cardinality). The payload is sent as a
serialized protobuf and resembles* the following:

```
[ H(x_1)^(c), H(x_2)^(c), ... , H(x_n)^(c) ]
```

3. Response (server)

For each encrypted element `H(x)^c` received from the client, the server
encrypts it again under the commutative encryption scheme with its secret key
`s`, computing `(H(x)^c)^s = H(x)^(cs)`. The result is sent back to the client
in a serialized protobuf and resembles* the following:

```
[ H(x_1)^(cs), H(x_2)^(cs), ... , H(x_n)^(cs) ]
```

4. Compute intersection (client)

The client decrypts each element received from the server's response using its
secret key `c`, computing `(H(x)^(cs))^(1/c) = H(x)^s`. It then checks whether
each decrypted element is present in the container received from the server, and
reports the number of matches as the intersection size.

It's worth noting that the protocol has several variants, some of which
introduce a small false-positive rate, while others do not generate false
positives. This behavior is selective, and the false-positive rate can be tuned.
The selection has implications on communication costs as well.

__NOTE resembles*__: The protocol has configurable **containers**. Golomb
Compressed Sets (`Gcs`) is the default container but it can be overridden to be
`BloomFilter` or `Raw` encrypted strings. `Gcs` and `BloomFilter` will have
false positives whereas `Raw` will not. Using `Raw` increases the communication
cost as it is sending raw strings over the wire while the other two options
drastically reduce the cost at the price of having false positives.

## Security

See [SECURITY.md](SECURITY.md).

## Requirements

There are requirements for the entire project which each language shares. There
also could be requirements for each target language:

### Global Requirements

These are the common requirements across all target languages of this project.

- A compiler such as clang or gcc
- [Bazel](https://bazel.build)

## Installation

The repository uses a folder structure to isolate the supported targets from one
another:

```
private_set_intersection/<target language>/<sources>
```

### C++

See the [C++ README.md](private_set_intersection/cpp/README.md)

### JavaScript

See the [JavaScript README.md](private_set_intersection/javascript/README.md)

### Go

See the [Go README.md](private_set_intersection/go/README.md)

### Python

See the [Python README.md](private_set_intersection/python/README.md)

### Rust

See the [Rust README.md](private_set_intersection/rust/README.md)

## Usage

A full description of the protocol can be found in the documentation of the
[PsiClient](private_set_intersection/cpp/psi_client.h) class. The corresponding
server class is [PsiServer](private_set_intersection/cpp/psi_server.h). An
example of how to interleave the different phases of the protocol can be found
in [psi_server_test.cpp](private_set_intersection/cpp/psi_server_test.cpp).

## Changes

See [CHANGES.md](CHANGES.md).

## Contributing

Pull requests are welcome. For major changes, please open an issue first to
discuss what you would like to change.

Please make sure to update tests as appropriate.

## Contributors

See [CONTRIBUTORS.md](CONTRIBUTORS.md).

## License

[Apache License 2.0](https://choosealicense.com/licenses/apache-2.0/)
