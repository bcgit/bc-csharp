# Bouncy Castle C# Specification & Interoperability

The following provides an overview of the formats, protocols and algorithms supported by the Bouncy Castle C# APIs, with links to the external standards that define them. It is the source for the C# Specification & Interoperability page on bouncycastle.org, and is updated with each release.

This page covers the Bouncy Castle C# APIs (the [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography) package). The FIPS, LTS and Java releases have their own documentation; the Certifications section below lists the FIPS certificates for the C# FIPS API.

## Packages and Standards

Bouncy Castle C# supports the following formats and standards.

| Supported Standard | External Reference |
|---|---|
| X.509 and PKIX certificates and CRLs | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280), [RFC 9925](https://www.rfc-editor.org/rfc/rfc9925) (unsigned certificates) |
| CMP: Certificate Management Protocol | [RFC 9810](https://www.rfc-editor.org/rfc/rfc9810), [RFC 4210](https://www.rfc-editor.org/rfc/rfc4210) |
| CMS/PKCS#7: Cryptographic Message Syntax | [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652), [RFC 9882](https://www.rfc-editor.org/rfc/rfc9882) (ML-DSA), [RFC 9814](https://www.rfc-editor.org/rfc/rfc9814) (SLH-DSA), [RFC 5753](https://www.rfc-editor.org/rfc/rfc5753) (ECC) |
| CRMF: Certificate Request Message Format | [RFC 4211](https://www.rfc-editor.org/rfc/rfc4211) |
| DTLS: Datagram Transport Layer Security 1.2 | [RFC 6347](https://www.rfc-editor.org/rfc/rfc6347) |
| OpenPGP | [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580), [RFC 4880](https://www.rfc-editor.org/rfc/rfc4880), [RFC 6637](https://www.rfc-editor.org/rfc/rfc6637) |
| PKCS#10: Certification Request Syntax | [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986) |
| PKCS#12: Personal Information Exchange Syntax | [RFC 7292](https://www.rfc-editor.org/rfc/rfc7292) |
| TLS: Transport Layer Security 1.2 and 1.3 | [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446), [RFC 5932](https://www.rfc-editor.org/rfc/rfc5932), [RFC 6209](https://www.rfc-editor.org/rfc/rfc6209), [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024) (hybrid ML-KEM key exchange), [draft-ietf-tls-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/) (ML-KEM key exchange), [draft-ietf-tls-mldsa](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/) (ML-DSA authentication), [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final) |
| TSP: Time-Stamp Protocol | [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161), [RFC 5035](https://www.rfc-editor.org/rfc/rfc5035) (ESS signing certificate) |
| Algorithm Identifiers for EdDSA and XDH | [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410) |
| Algorithm Identifiers for HSS/LMS | [RFC 9802](https://www.rfc-editor.org/rfc/rfc9802) |
| Algorithm Identifiers for ML-DSA | [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881) |
| Algorithm Identifiers for ML-KEM | [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935) |
| Algorithm Identifiers for SLH-DSA | [RFC 9909](https://www.rfc-editor.org/rfc/rfc9909) |

## Certifications

The following lists certifications with relevant links to certificates and documentation.

| Type | Language | Version | External Reference | Documentation |
|---|---|---|---|---|
| FIPS 140-2 | C# | 1.0.2 | [Cryptographic Module Validation Program (CMVP) Certificate #4416](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4416) (Historical) | [BC-FNA 1.0.2 (Bouncy Castle FIPS .NET API) User Guide](https://downloads.bouncycastle.org/fips-csharp/docs/BC-FNA-UserGuide-1.0.2.pdf) |
| FIPS 140-2 | C# | 1.0.1.1 | [Cryptographic Module Validation Program (CMVP) Certificate #2792](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/2792) (Historical) | [BC-FNA (Bouncy Castle FIPS .NET API) User Guide](https://downloads.bouncycastle.org/fips-csharp/docs/BC-FNA-UserGuide-1.0.1.pdf) |

For more information about the Bouncy Castle FIPS .NET API and how it presents cryptography, refer to [The Bouncy Castle FIPS C# API in 100 Examples](https://downloads.bouncycastle.org/fips-csharp/docs/BCFipsCSharp100.pdf) and sample code at [https://downloads.bouncycastle.org/fips-csharp/code/bc-fips-100-csharp.zip](https://downloads.bouncycastle.org/fips-csharp/code/bc-fips-100-csharp.zip). Downloads and further documentation are available from [Download Bouncy Castle C# .NET FIPS](https://www.bouncycastle.org/download/bouncy-castle-c-fips/) and [Documentation Bouncy Castle C# .NET](https://www.bouncycastle.org/documentation/documentation-c/).

## Algorithms & Key Types

Bouncy Castle supports the following public key algorithm types and key sizes/curves.

| Algorithm | External Reference |
|---|---|
| Diffie-Hellman | [SP 800-56A](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final) |
| DSA | FIPS PUB 186-4, [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) |
| DSTU 4145 | DSTU 4145-2002 |
| ECDSA/ECDH | X9.62, FIPS PUB 186-4, [RFC 5639](https://www.rfc-editor.org/rfc/rfc5639), [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979), [SP 800-56A](https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final) |
| EdDSA/XDH | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032), [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748), [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410) |
| ElGamal | [RFC 4880](https://www.rfc-editor.org/rfc/rfc4880) |
| GOST | [RFC 4490](https://www.rfc-editor.org/rfc/rfc4490), [RFC 7836](https://www.rfc-editor.org/rfc/rfc7836) |
| RSA | [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017), FIPS PUB 186-4, SP 800-56B |
| SM2 | [RFC 8998](https://www.rfc-editor.org/rfc/rfc8998) |

The post-quantum public key algorithms are listed [below](#post-quantum-algorithm-support).

### Symmetric Key Algorithms

Bouncy Castle supports the following symmetric key algorithms.

| Algorithm | External Reference |
|---|---|
| AES | FIPS PUB 197, [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394), [RFC 5649](https://www.rfc-editor.org/rfc/rfc5649) |
| ARIA | [RFC 5794](https://www.rfc-editor.org/rfc/rfc5794) |
| Ascon (AEAD) | [SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final) |
| Camellia | [RFC 3713](https://www.rfc-editor.org/rfc/rfc3713), [RFC 3657](https://www.rfc-editor.org/rfc/rfc3657) |
| CAST5 | [RFC 2144](https://www.rfc-editor.org/rfc/rfc2144) |
| CAST6 | [RFC 2612](https://www.rfc-editor.org/rfc/rfc2612) |
| ChaCha20, ChaCha20-Poly1305 | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) |
| XChaCha20, XChaCha20-Poly1305 | [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/) |
| DSTU 7624 | DSTU 7624:2014 |
| GOST 28147 | [RFC 5830](https://www.rfc-editor.org/rfc/rfc5830) |
| Grain-128AEAD | [NIST Lightweight Cryptography finalist](https://csrc.nist.gov/projects/lightweight-cryptography/finalists) |
| HC | eSTREAM Project |
| RC2 | [RFC 2268](https://www.rfc-editor.org/rfc/rfc2268), [RFC 3217](https://www.rfc-editor.org/rfc/rfc3217) |
| RC5 | [RFC 2040](https://www.rfc-editor.org/rfc/rfc2040) |
| Salsa20 | eSTREAM Project |
| SEED | [RFC 4269](https://www.rfc-editor.org/rfc/rfc4269) |
| SM4 | [RFC 8998](https://www.rfc-editor.org/rfc/rfc8998) |
| TripleDES | FIPS PUB 46-3, [RFC 3217](https://www.rfc-editor.org/rfc/rfc3217) |

## Message Digests and Expandable Output Functions

Bouncy Castle supports the following Message Digests and Expandable Output Functions (XOFs).

| Algorithm | External Reference |
|---|---|
| Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128 | [SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final) |
| BLAKE2 | [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693) |
| BLAKE3 | [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs) |
| cSHAKE-128, cSHAKE-256 | [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) |
| KMAC-128, KMAC-256 | [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) |
| MD5 | [RFC 1321](https://www.rfc-editor.org/rfc/rfc1321) |
| ParallelHash-128, ParallelHash-256 | [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) |
| RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320 | ISO/IEC 10118-3 |
| SHA-1 | FIPS PUB 180-4 |
| SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | FIPS PUB 180-4 |
| SHA3-224, SHA3-256, SHA3-384, SHA3-512 | FIPS PUB 202 |
| SHAKE-128, SHAKE-256 | FIPS PUB 202, [RFC 8702](https://www.rfc-editor.org/rfc/rfc8702) |
| SM3 | [RFC 8998](https://www.rfc-editor.org/rfc/rfc8998) |
| Tiger | Project NESSIE |
| TupleHash-128, TupleHash-256 | [SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) |
| Whirlpool | Project NESSIE, ISO/IEC 10118-3 |

## Post-Quantum Algorithm Support

The following post-quantum algorithms are standardized and implemented.

### Key Encapsulation Mechanisms (KEMs)

| Key Encapsulation Mechanism | External Reference |
|---|---|
| ML-KEM | [FIPS PUB 203](https://csrc.nist.gov/pubs/fips/203/final) |

### Signature Algorithms

| Signature Algorithm | External Reference |
|---|---|
| ML-DSA | [FIPS PUB 204](https://csrc.nist.gov/pubs/fips/204/final) |
| SLH-DSA | [FIPS PUB 205](https://csrc.nist.gov/pubs/fips/205/final) |
| LMS/HSS | [SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final), [RFC 8554](https://www.rfc-editor.org/rfc/rfc8554), [RFC 8708](https://www.rfc-editor.org/rfc/rfc8708) |

### Hybrid and Composite Algorithms

| Algorithm | External Reference |
|---|---|
| Composite ML-DSA signatures | [RFC 10073](https://www.rfc-editor.org/rfc/rfc10073) |

## Other Post-Quantum Algorithms

For further details on these algorithms, refer to [NIST Post-Quantum Cryptography](https://csrc.nist.gov/Projects/post-quantum-cryptography).

The post-quantum algorithms below have been submitted to the NIST standardization process. Apart from FrodoKEM and Classic McEliece, which ISO/IEC 18033-2:2006/Amd 2:2026 standardizes, none is yet standardized: they are available for experimenting and hybrid cryptography, but are unsuitable for long-term use until standardized.

### Key Encapsulation Mechanisms (KEMs)

| Key Encapsulation Mechanism | Status |
|---|---|
| HQC | Selected by NIST for standardization ([NIST IR 8545](https://csrc.nist.gov/pubs/ir/8545/final)) |
| Classic McEliece | Standardized in [ISO/IEC 18033-2:2006/Amd 2:2026](https://www.iso.org/standard/86890.html); NIST Round 4 candidate; no longer recommended by BSI, and likely to be deprecated |
| FrodoKEM | Standardized in [ISO/IEC 18033-2:2006/Amd 2:2026](https://www.iso.org/standard/86890.html); NIST Round 3 alternate candidate; recommended by BSI |
| BIKE | NIST Round 4 candidate, not selected |
| NTRU | NIST Round 3 finalist, not selected |
| NTRU Prime (Streamlined NTRU Prime, NTRU LPRime) | NIST Round 3 alternate candidate, not selected |
| SABER | NIST Round 3 finalist, not selected |

### Signature Algorithms

| Signature Algorithm | Status |
|---|---|
| Falcon | Selected by NIST for standardization as FN-DSA (FIPS 206, in development) |
| Picnic | NIST Round 3 alternate candidate, not selected |
| CRYSTALS-Dilithium, SPHINCS+ (Round 3 versions) | Superseded by ML-DSA and SLH-DSA; deprecated, and retained only for compatibility |

## CRL and OCSP

Bouncy Castle supports the following CRL formats and standards.

| Supported Standard | External Reference |
|---|---|
| CRL creation and processing | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) |
| Online Certificate Status Protocol (OCSP) | [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960), [RFC 2560](https://www.rfc-editor.org/rfc/rfc2560) |

## Certificate Enrollment Protocols

The following lists Certificate Enrollment Protocols and/or interfaces.

| Protocol/Interface | External Reference |
|---|---|
| Certificate Management Protocol (CMP) | [RFC 9810](https://www.rfc-editor.org/rfc/rfc9810), [RFC 4210](https://www.rfc-editor.org/rfc/rfc4210) |
| Certificate Request Message Format (CRMF) | [RFC 4211](https://www.rfc-editor.org/rfc/rfc4211) |
