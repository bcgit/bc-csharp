# BouncyCastle strip v2: plan (turboHTTP TLS fallback)

Revision 6.3. Revision 6 folded in review round 4 on rev 5: a build dry run on both define sets, a security check
against master, and a fresh cold read. 6.1 applied the round-5 readiness review. 6.2 applied the first closing review
(Fable, high effort): the E6 aliases fix plus minor fixes. 6.3 applied the second closing review: an RSA exponent bound
(major), an internal-API fix in the smoke suite, and nits. The third closing review found only minor items and nits;
they are folded in, and **the review cycle is closed**.

**Scope:** this repo only. The output is the stripped BouncyCastle source with its namespace rewritten. turboHTTP work
is tracked as issues in fatal10110/turboHTTP (§8). ✔ marks claims re-verified against code.

**Status:** ready for the `--report` bootstrap (§6 step 1), using the provisional define sets. Enforce mode waits for
`unity-defines.txt` from #141.

## 1. Current state

| Item | Value |
|---|---|
| Vendored in turboHTTP | `Runtime/Transport/BouncyCastle/Lib`: 1268 `.cs`, global whole-token rewrite `Org.BouncyCastle` → `TurboHTTP.SecureProtocol.Org.BouncyCastle` (string literals included), turboHTTP commit e172f90 (2026-02-13) |
| Source | `origin/strip-gpt` (6d6b72c1) plus a 20-file GOST-removal patch that exists **only** in turboHTTP |
| Upstream base | master @ 5200dfdf (2026-01-09). master is now 820 commits ahead (head 7c9c8d5a); 562 kept files changed |

### Defects in the shipped strip

1. ✔ **RSA key exchange is offered but cannot complete.** `HasRsaEncryption()` returns true, but
   `BcTlsRawKeyCertificate.CreateEncryptor` throws `internal_error`.
2. ✔ **AES-256-GCM is never offered.**
3. ✔ **No BouncyCastle MIT notice.**
4. ✔ **`X509Certificate.Verify`/`IsSignatureValid` throw.** This is acceptable under decision A.
5. ✔ **OCSP stapling is requested by default** (`AbstractTlsClient.cs:121-124`) and never validated.
6. **AES and GHASH are table-based under Unity defines** (no intrinsics), so they leak through cache timing.
7. ✔ **No handshake timeout in the stream API.** The vendored `TlsProtocol` never calls `GetHandshakeTimeoutMillis`.
8. **Upstream fixes missing on the client path:**
   - ✔ `89c81b0d` + `b99f4e3d`: ASN.1 depth limit. About 8K nesting levels fit in a 32 KB message, which risks an
     uncatchable `StackOverflowException`.
   - ✔ `bd03e38b`: quadratic `X509Name.ToString`.
   - ✔ `ab4eb3d2`: the stream API honours `GetHandshakeTimeoutMillis`, checked between records.
   - `8b675866`: an unwiped ECDH `BigInteger`.
   - `6ec5c6c3`: TLS 1.3 CertificateEntry checks. They are stricter, so interop needs a test.
   - `445150e3`: the must-staple NRE.
   - Defence in depth: `d12f3c1e`, `65b8a1a4`, `01a513c0`, `3a81673a`, `177e8e65`, `3bfc3c00`, `37fdb318`.
9. **Not reproducible.** Cherry-picking the fixes onto the old strip fails for 7 of 11 commits.

### Upstream regression to neutralise

- ✔ `8ee52127` runs a Miller-Rabin test on every peer RSA public key (`RsaKeyParameters.cs:84-92`). On desktop that
  costs 1.14 s for an 8192-bit key and 9.3 s for a 16384-bit one. Fixed by E7.

## 2. Decisions taken for the strip

These are the plan's defaults. The user and turboHTTP confirm or override them in #141.

| | Decision | Effect on strip |
|---|---|---|
| A | **Chain validation is outside BC.** Mobile uses the native verifier (iOS `SecTrustEvaluateWithError` + `SecPolicyCreateSSL(host)`, Android `X509TrustManagerExtensions.checkServerTrusted`) on the DER chain BC received. Editor and desktop use .NET `X509Chain`; whether Unity Mono's `X509Chain` handles ECDSA and name constraints must be validated in #33, and that result decides A. **No BC PKIX, and no BC certificate-signature verification.** | `pkix/**` denied. `X509Certificate.Verify` keeps throwing (E8). Re-enabling BC-side verification later adds a `TurboVerifierFactory` (spec kept in Appendix A). |
| B | **No TLS 1.2 CBC.** | E1 |
| C | **No X25519MLKEM768 for now.** Re-enabling it means changing E1 `HasNamedGroup`, un-denying `*mlkem*`, and overriding `GetSupportedGroups`/`GetEarlyKeyShareGroups`. | E1, deny |
| D | **No OCSP request** (E4 + #142). Consequence: **must-staple is not enforced**, because `CheckTlsFeatures` only enforces features the client offered. `asn1/ocsp` stays, since the TLS API needs it. | E4 |
| E | **No Ed25519 or Ed448 certificates.** | E1, E5, deny |
| F | **No TLS 1.3 resumption.** It needs no strip files. | none |
| G | **AES and GHASH timing:** use the `AesLightEngine` 256 B S-box when there is no AES-NI, and always use `BasicGcmMultiplier`. GHASH becomes constant-time. AES still does secret-indexed lookups over 4 cache lines, so the leak is **reduced, not removed**. Under Unity defines `IsHardwareAccelerated` is always false, so even AES-NI desktops run the light engine. ChaCha20 goes first (desktop: 391 MB/s, against 142 MB/s for AES-GCM). Mobile throughput is measured in #141. `BasicGcmMultiplier` is `[Obsolete]`; revisit at the BC v3 bump. | E14 |
| P-521 | **Offer secp521r1** (E1 + E4). Under TLS 1.2 a server only picks an ECDSA certificate whose curve the client lists, and the curve code is kept for P-521 keys anyway. | E1, E4 |

## 3. Edge cuts (commit series on `strip-v2`)

**Policy:**
- Deny whole subsystems, not shared helpers. These helpers stay: `ParameterUtilities`, `DigestUtilities`,
  `math/binpoly`, `asn1/ocsp`, and the `crypto/operators/Default*` calculators.
- Cut only where the deny list forces it, plus the behavioural cuts E1–E4, E7 and E14.
- Make each cut at the call site. Turbo-owned files live in `crypto/src/turbo/`, namespace `Org.BouncyCastle.Turbo`,
  with an MIT header.
- Every hunk carries a `// turbo-strip:` marker.

| # | File(s) | Cut |
|---|---|---|
| E1 | `tls/crypto/impl/bc/BcTlsCrypto.cs` | **Cipher, key-exchange and group support:** `HasEncryptionAlgorithm` allows AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 only. `HasNamedGroup` allows x25519, secp256r1, secp384r1 and secp521r1. `HasRsaEncryption`, `HasDHAgreement` and `HasKemAgreement` return false. `CreateDHDomain`, `CreateKemDomain` and `CreateSrp6*` throw; the `CreateSrp6*` methods are `abstract` in `AbstractTlsCrypto.cs:90-94` ✔, so they must stay and throw. Remove the `BcTlsMLKemDomain`/`BcX448Domain` references. **ClientHello `signature_algorithms`:** `HasSignatureAndHashAlgorithm` whitelists the hashes {Intrinsic, SHA-256, SHA-384, SHA-512}. This method builds the extension (`TlsUtilities.cs:1053-1060` → `BcTlsCrypto.cs:418-436`) ✔, and Intrinsic keeps the TLS 1.3 `rsa_pss_*` schemes. The hash check runs **before** the `IsMLDsaScheme`/`IsSlhDsa` early return (`:420-425`), and those schemes return false. `HasCryptoSignatureAlgorithm` (`:255-280`) is trimmed to match; it has no TLS caller. `HasSignatureAlgorithm` keeps only rsa, ecdsa and rsa_pss_*; it drops ed25519, ed448, **dsa** and the **ecdsa_brainpool*tls13** values (`:394-406`). `HasSignatureScheme` stays consistent with it: false for ML-DSA, SLH-DSA and `sm2sig_sm3`. Without this, the default list (`TlsUtilities.cs:117-147`) would still offer DSA and ML-DSA. **Digests:** remove `Gost3411_2012_256Digest` (`:527`, `:552`) and `gostr3411_2012_256` from `HasCryptoHashAlgorithm`. |
| E2 | `tls/DefaultTlsKeyExchangeFactory.cs` | The DH, DHE, anon, PSK, SRP, RSA and static-ECDH factory methods throw `TlsFatalAlert(internal_error)`. |
| E3 | `tls/DefaultTlsClient.cs` | Default suites. TLS 1.3: CHACHA20, AES_128_GCM, AES_256_GCM. TLS 1.2: ECDHE_{ECDSA,RSA} × {CHACHA20_POLY1305_SHA256, AES_128_GCM_SHA256, AES_256_GCM_SHA384}. |
| E4 | `tls/AbstractTlsClient.cs` | `GetDHGroupVerifier`/`GetSrpConfigVerifier` return null (`:101-109`). `GetCertificateStatusRequest` returns null (`:121-124`). `GetMultiCertStatusRequest` already returns null on master (`:127-130`), so it needs no change. `GetSupportedGroups` adds secp521r1 (`:155-160`). The handshake timeout stays a consumer override (#142). |
| E5 | `tls/crypto/impl/bc/BcTlsRawKeyCertificate.cs` + `turbo/TurboKeyFactory.cs` | Route `PublicKeyFactory.CreateKey` (`:469`) to `TurboKeyFactory`. **Accepted:** rsaEncryption and id-RSASSA-PSS keys of **≥ 2048** bits (E7 caps them at 8192); EC keys on a *named* P-256/384/521 curve. **Rejected:** explicit EC parameters and anything else. **The RSA public exponent must satisfy
`e.BitLength <= 64`, for rsaEncryption and id-RSASSA-PSS alike.** Master only checks that `e` is positive and odd
(`RsaKeyParameters.cs:35-38`) ✔. With an 8192-bit `n` and an approximately 8192-bit `e`, every TLS 1.2
ServerKeyExchange and TLS 1.3 CertificateVerify check costs about 1.16 s on desktop, which re-opens the denial of
service that E7 closes. OpenSSL applies the same 64-bit bound when `n` is larger than 3072 bits. **Construct keys
only through the public constructors, so master's validation runs.** RSA uses `new RsaKeyParameters(false, n, e)`, which checks for an even modulus, small
factors and the size cap (`RsaKeyParameters.cs:75-99`). EC decodes the point with the named curve's
`Curve.DecodePoint` and wraps it in `ECPublicKeyParameters`, which runs `ValidatePublicPoint`. Parameters that are
not a named-curve `X962Parameters` are rejected. Cut the Ed25519/Ed448/SM2/DSA and PqcUtilities/ML-DSA/SLH-DSA branches. Drop the unused `using …Asn1.Cmp` (`:5`). Rejections become `TlsFatalAlert(unsupported_certificate)` via `GetPublicKey` (`:465-474`). The TLS 1.3 ECDSA scheme↔curve binding is not added here; report it upstream. |
| E6 | `crypto/ec/CustomNamedCurves.cs`, `asn1/x9/ECNamedCurveTable.cs` | Only what deny forces. In CustomNamedCurves, drop the SecT* and SM2 `DefineCurve` lines, their holder classes, **and the B-163…B-571 / K-163…K-571 `DefineCurveAlias` lines (`:842-852`)**. `DefineCurveAlias` throws `InvalidOperationException` when the OID is missing (`:795-801`) ✔, and that exception in the static constructor would break every EC lookup, P-256/384/521 included (`BcTlsECDomain` → `ECDomainParameters.LookupName` → `ECUtilities.FindECCurveOid`). From ECNamedCurveTable, drop the `ECGost3410NamedCurves` lookup. Leave the SEC/NIST/X962 tables alone; TurboKeyFactory already restricts curves. |
| E7 | `crypto/parameters/RsaKeyParameters.cs` (`:84`, `:92`) | Defaults: `RsaMaxSize` = 8192, `RsaMaxMRTests` = 0. |
| E8 | `x509/X509Certificate.cs` | Route `CreatePublicKey` (`:619`) to `TurboKeyFactory`. `TurboKeyFactory` turns **every** failure, malformed SPKI included, into `ArgumentException`. Callers get it unwrapped, and #33's validator must catch it. `X509Certificate.ToString()` calls `GetPublicKey()` (`:431`), so it is wrapped in try/catch and prints `<unsupported key>` instead. `IsSignatureValid`/`Verify`/the alternative-signature methods (`:513`, `:519`, `:556`) throw `NotSupportedException` (decision A). `SigAlgName` uses a small turbo OID→name map and returns the OID string for unknown OIDs, because `ToString` depends on it. After this cut, `Asn1Signature.cs` and `X509SignatureUtil.cs` leave the closure. |
| E9 | `x509/extension/X509ExtensionUtil.cs` (`:16-17`) | Remove the `CalculateKeyIdentifier(AsymmetricKeyParameter)` overload, which uses `SubjectPublicKeyInfoFactory`. Its callers are `SubjectKeyIdentifierStructure.cs:20` and `AuthorityKeyIdentifierStructure.cs:38` ✔. If either enters the closure, cut their `AsymmetricKeyParameter` constructors too; the referrer sweep should then report them as expected, not as a surprise. |
| E10 | `crypto/generators/ECKeyPairGenerator.cs` (`:38-46`) | Remove the `ECGost3410Utilities` branch. |
| E11 | `security/DigestUtilities.cs` (`:403-408`) | Remove the GOST3411, GOST3411-2012 and Dstu7564 entries. Reached via `SecureRandom.cs:27`. |
| E12 | `tls/crypto/impl/bc/BcTlsHmac.cs` (`:31`) | Inline `MacUtilities.DoFinal(m_hmac)`. That is MacUtilities' only caller in the current closure. `crypto/operators/DefaultMacResult.cs:17` also calls it ✔, so if that file ever enters the closure, MacUtilities comes back with its `Gost28147Mac` reference. The referrer sweep catches that; this cut is not a permanent guarantee. |
| E13 | Any file builds 3a/3b flag | **General rule:** fix every `#if`-guard mismatch that the captured define sets expose, with the smallest guard edit, and report each one upstream. Known cases: with `NETSTANDARD2_1_OR_GREATER` but no `NETSTANDARD1_x_OR_GREATER`, 11 files fail (`using` lines guarded by `NETSTANDARD1_0_OR_GREATER`/`NET45_OR_GREATER`). With the full SDK set, only `Poly1305.cs:3-4` vs `:254,257` fails ✔. The 11-file case was measured on
`NETSTANDARD;NETSTANDARD2_1;NETSTANDARD2_1_OR_GREATER`; across all of `crypto/src` that set fails in 17 files, 11 of
them in the closure. Known offenders: `crypto/util/Pack.cs:6-8`, `util/io/Streams.cs`, `Poly1305.cs`,
`ChaCha7539Engine.cs`, `tls/TlsStream.cs`, `util/io/{Filter,Pushback}Stream.cs`, `util/io/Base{Input,Output}Stream.cs`,
`crypto/io/{Cipher,Digest,Mac,Signer}Stream.cs`, `crypto/io/{Digest,Mac,Signer}Sink.cs`, and the denied
`math/ec/rfc7748/X448Field.cs` (17 in total). |
| E14 | `crypto/modes/GCMBlockCipher.cs` (file name upper-case) `CreateGcmMultiplier` (`:49-54`); `tls/crypto/impl/bc/BcTlsCrypto.cs` `CreateAesEngine` (`:678`) | `CreateGcmMultiplier` always returns `new BasicGcmMultiplier()`. This is one internal line and avoids the `[Obsolete]` constructor. `CreateAesEngine` returns `AesUtilities.IsHardwareAccelerated ? AesUtilities.CreateEngine() : new AesLightEngine()`. |

**`deny.txt`.** Paths are relative to `crypto/src`, matched case-insensitively against files *added by the closure*.
- Registries: `security/{Cipher,Signer,Generator,Agreement,Wrapper,Pbe,Kem}Utilities.cs`, `security/PublicKeyFactory.cs`,
  `x509/SubjectPublicKeyInfoFactory.cs`, `x509/X509SignatureUtil.cs`, `crypto/operators/{Asn1*,Cms*,GenericKey*}.cs`.
- GOST, SM2 and DSTU: `**/*gost*`, `**/*sm2*`, `**/*dstu*`.
- Post-quantum: `**/*mldsa*`, `**/mldsa/**`, `**/*mlkem*`, `**/mlkem/**`, `**/*slhdsa*`, `**/slhdsa/**`, `pqc/**`,
  `tls/crypto/impl/PqcUtilities.cs`.
- Ed448 and X448: `**/*ed448*`, `**/*x448*`.
- Ed25519 signing: `crypto/signers/Ed25519*`, `crypto/parameters/Ed25519*`, `crypto/generators/Ed25519*`,
  `tls/crypto/impl/bc/BcTlsEd25519Signer.cs`. Do **not** deny `math/ec/rfc8032/Ed25519.cs`: X25519 uses it ✔
  (`rfc7748/X25519.cs:306`).
- Binary-field curves: `math/ec/custom/sec/SecT*`.
- Unused subsystems: `crypto/fpe/**`, `cms/**`, `pkcs/**`, `openpgp/**`, `bcpg/**`, `pkix/**`.

Rev-5 dry run, unpatched, union of both define sets: 931 BC files and 164 deny hits. Every referrer it **recorded**
is covered by E1, E5, E6, E8, E9, E10, E11 or E12. About 765 files remain after the deny list. The prototype records
only the first referrer of each denied file, so this is not yet proof of full coverage. `--report` adds a
**referrer sweep** (§5 step 2) that gives the complete set.

**`budget.txt`.** A single total cap: the first enforced count + 10%. Per-directory counts are printed for review.

**`roots-extra.cs` (contract).** These are the BC APIs turboHTTP uses, or will use, under decision A:
- `TlsUtilities.CheckPeerSigAlgs`. It treats the last certificate as the trust anchor, so #33 passes it the
  platform-built path, not the raw server chain. For PSS-signed certificates it calls `SupportsSignatureAlgorithmCA`
  → `GetPublicKey()` on the issuer (`TlsUtilities.cs:4766-4790`) ✔. A CA or anchor key outside the TurboKeyFactory
  whitelist therefore fails with `TlsFatalAlert(unsupported_certificate)`, and #33 must catch that as well;
- `Certificate.GetCertificateAt(i).GetEncoded()`, and `TlsCrypto.CreateCertificate(byte[])` (`TlsCrypto.cs:119`) ✔.
  #33 needs the latter to wrap the DER of a platform-built path, which may include certificates the server did not
  send, into `TlsCertificate[]` for `CheckPeerSigAlgs`. It is in the closure anyway;
- `X509Certificate`: `SubjectDN`, `NotBefore`/`NotAfter`, `GetSubjectAlternativeNames`, `GetPublicKey`;
- `ExtendedKeyUsage`, `BasicConstraints`, `KeyUsage`, `GeneralName` (iPAddress).

New entries come from #33 via #141. The contract is compiled in the closure and again against the rewritten
separate-assembly DLL (3c), with the namespace rewritten.

## 4. Tooling and branch

- **Branch `strip-v2`.** It is cut from `BASE` (7c9c8d5a at bootstrap time, recorded in `strip/BASE`).
  - Commit 1 holds the tooling: `STRIP_PLAN_V2.md` and `strip/`, which are untracked on master today.
  - The E-cut commits follow, one per E-number.
  - A bump rebases the whole series with `git rebase --onto NEWBASE OLDBASE strip-v2`, with `rerere` enabled.

```
strip/
  BASE, ROOTS_SHA       # committed here; ROOTS_SHA = turboHTTP commit the roots came from
  roots/                # COMMITTED: 3 consumer files (rewrite reversed), RootStubs.cs (ITlsProvider, TlsResult 5-arg
                        #   ctor, UnityEngine.Scripting.PreserveAttribute), roots-extra.cs
  deny.txt  budget.txt
  unity-defines.txt     # [netstandard21] / [netframework] sections, one DefineConstants line each, from #141.
                        #   Until then, --report runs three provisional sets:
                        #   [min] NETSTANDARD;NETSTANDARD2_1 = the no-Span floor (pure legacy paths);
                        #   [partial] [min] + NETSTANDARD2_1_OR_GREATER = the E13 11-file case;
                        #   [sdk] = the full SDK netstandard2.1 implicit set = Span paths, Poly1305 only.
                        #   That way the guard fixes are known whichever way #141 answers.
  unity-probe/          # DefineProbe.cs — optional Editor cross-check of the captured sets
  Closure.csproj        # EnableDefaultCompileItems=false; LangVersion 9; AllowUnsafeBlocks=false;
                        #   DisableImplicitFrameworkDefines=true; single TargetFramework per run (no multi-targeting):
                        #   netstandard2.1 refs for [netstandard21];
                        #   Microsoft.NETFramework.ReferenceAssemblies.net471 for [netframework] (Unity's 4.7.x
                        #   surface; ns2.0 refs would only produce false failures and needless E13 edits);
                        #   DisableImplicitConfigurationDefines=true (otherwise -c <Config> adds DEBUG/RELEASE/STRIP);
                        #   strip.sh asserts set(csc /define:) == captured set, ignoring empty entries (binlog);
                        #   strip.sh runs `dotnet restore` before the --no-restore loop;
                        #   defines are passed via a generated .props file assigning <DefineConstants> (which also
                        #   replaces the SDK's TRACE). `-p:DefineConstants=a;b` fails with MSB1006 because of the semicolons.
  tool/                 # Python 3: index.py, closure.py (emits namespace stubs every iteration; reproduced CLEAN at
                        #   934 files / 27 iterations), deny.py. Still to do (§5 step 2):
                        #   - C#-lookup-order resolution and the extension-method index;
                        #   - one build per define set;
                        #   - stubs written outside crypto/src;
                        #   - the referrer sweep;
                        #   - deny.py reading strip/deny.txt (drop the allow4/deny4 names).
                        #   roots/, Closure.csproj, deny.txt and strip.sh are not written yet.
  smoke/                # net8 harness (§5 step 5)
  notices/  strip.sh
```

**Prerequisites:**
- .NET SDK 8;
- Python 3;
- Homebrew OpenSSL 3.x;
- a turboHTTP checkout, needed only for `--refresh-roots`.

## 5. Steps (`strip.sh [--report] [--refresh-roots --turbohttp <path>]`)

1. **Prepare.** Check out `strip-v2`. With `--refresh-roots`, re-copy `roots/` and update `ROOTS_SHA`.
2. **Closure** (`tool/closure.py`). This is a fixpoint over the **union of both define sets**: iterate until neither
   build adds a file. Seed with `roots/` + `crypto/src/turbo/`.
   - **Namespace stubs:** emit `namespace X { }` stubs **on every iteration** for every namespace a `using` names,
     including intermediate namespaces. Without them, declaration-level CS0234 errors hide the body errors and the loop
     stalls; the prototype stalled at 145 files. At the fixpoint, prune the stubs to namespaces that a kept `using`
     references and that have no kept file, then rebuild both sets. The survivors ship as
     `Lib/_TurboNamespaceStubs.cs`.
   - **Index:** declared types keyed by (namespace, name, generic arity), with nested types mapped to their outer file.
     A separate extension-method index maps the `this`-parameter methods of static classes.
   - **Resolution:** CS0246, CS0103, CS0305, CS0308 and CS0426 resolve in **C# lookup order**: the erroring file's
     enclosing namespaces from innermost outward, each followed by its usings. Every candidate is added only on a
     genuine same-level tie. CS0234 resolves by namespace + name, and never for `using` lines (the stubs handle those).
     CS1061 and CS1501 resolve through the extension-method index. **Partial types** (e.g. `math/binpoly/BinPolyMulBase*.cs`,
     `x86/v128/Kernels.*`) are one unit: all their parts are added together, and they never count as an ambiguity.
   - **Fail checks run at the fixpoint only:**
     - unresolved errors (printed);
     - a deny hit, naming the kept referrer (`--report` logs these instead of failing). **Referrer sweep:** after
       the fixpoint, build (closure − denied + stubs) once per define set. Every kept file that then fails to compile
       is a referrer that needs a cut. That gives the complete list, not just the first referrer the loop recorded;
     - a budget overrun.
3. **Builds.**
   - (a) [netstandard21] and (b) [netframework], on the stripped tree.
   - (c) the rewritten tree (step 4) for **each** define set, giving `TurboBC.ns21.dll` and `TurboBC.netfx.dll`.
     Against each, compile the unmodified consumer files, `RootStubs.cs` and the rewritten `roots-extra.cs` as a
     separate assembly.
   - Suppress CS3021.
   - The Unity compile in #141 is the real check.
4. **Namespace rewrite.** Global whole-token `\bOrg\.BouncyCastle\b` → `TurboHTTP.SecureProtocol.Org.BouncyCastle`. It
   covers usings and aliases (✔ `GeneralName.cs:7`), crefs, and string-literal property keys, so another BC copy in
   the process can't share our limits.
5. **Smoke suite.** Mandatory before handover; results go in `STRIP_INFO.md`.
   - **Harness:** a net8 console that references `TurboBC.*.dll` (client) **and** a full upstream build of `BASE`
     (server and tooling). The two coexist because of the namespace rewrite.
     - The client is `SmokeTlsClient : DefaultTlsClient`, mirroring `TurboTlsClient`: ALPN, SNI, TLS 1.2/1.3, and
       `GetHandshakeTimeoutMillis` = 30000. `TurboTlsClient` itself is `internal sealed`.
     - Custom servers are written on the upstream `TlsServerProtocol` where OpenSSL can't produce the case.
   - **Curve lookup, per DLL, first:** resolve secp256r1, secp384r1 and secp521r1 by name and by OID. Use only public
     API, because the harness is an external assembly and `ECUtilities` is `internal` ✔:
     `CustomNamedCurves.GetOid`/`GetByOid` (which trigger its static constructor, the E6 case),
     `ECDomainParameters.LookupName` and `ECNamedDomainParameters.LookupOid`. This catches static-initializer failures
     before interop.
   - **KATs, per DLL:** AES-GCM (light engine + Basic multiplier), ChaCha20-Poly1305, X25519, ECDSA P-256/384/521
     verify, RSA PKCS#1 and PSS verify, SHA-256/384/512, HMAC, TLS 1.3 HKDF. Take the vectors from the upstream
     `crypto/test` sources.
   - **Interop (OpenSSL 3 `s_server`):**
     - every E3 suite × {x25519, P-256, P-384, P-521} × RSA/ECDSA P-256/384/521 certificates, with ALPN `h2`;
     - RSA-kx-only, DHE-only and CBC-only servers: the handshake fails with a fatal alert from either side (usually
       the server's `handshake_failure`, since E3 never offers those suites).
   - **ClientHello assertion** (exact allow-lists):
     - suites are exactly E3 followed by `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (0x00FF), which BC appends when there
       is no `renegotiation_info` extension (`TlsClientProtocol.cs:1845-1852`) ✔, and nothing else;
     - groups are exactly {x25519, secp256r1, secp384r1, secp521r1};
     - `signature_algorithms` is exactly, in this order: ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384,
       ecdsa_secp521r1_sha512, rsa_pss_pss_sha256/384/512, rsa_pss_rsae_sha256/384/512, rsa_pkcs1_sha256/384/512.
       That is `TlsUtilities.CreateDefaultSupportedSigAlgs` (`:117-147`) ✔ filtered by E1;
     - there is no `status_request`/`status_request_v2`.
   - **Hostile inputs** (custom upstream server where needed; worker thread with a 256 KB stack):
     - the deepest nesting that fits a 32 KB Certificate message → depth exception;
     - more than 16K levels fed directly to `Asn1InputStream` → depth exception;
     - an 8192-bit RSA key is accepted in under 50 ms;
     - an 8193-bit key and a 1024-bit key are rejected;
     - an 8192-bit `n` with a 65-bit or larger `e` is rejected, via TLS and via `X509Certificate.GetPublicKey`;
       keys with `e` = 3 and `e` = 65537 are accepted;
     - explicit EC parameters are rejected via TLS and via `X509Certificate.GetPublicKey`.
   - **Timeout** (only effective after the re-vendor, `ab4eb3d2`):
     - a custom server trickling one record every few seconds → abort at about 30 s;
     - a silent peer → aborted only by the socket `ReceiveTimeout`, which the harness sets (#142 requires it of
       turboHTTP).
6. **Package** into `strip/out/`.
   - **`Lib/**`:** every file and folder gets a `.meta` with GUID = `md5("turbohttp-bc:" + relpath)`, where relpath is
     relative to `Lib/` with `/` separators; nothing references them. Use MonoImporter for `.cs`, folderAsset for
     directories, TextScriptImporter for `LICENSE.md`.
   - **`Lib/LICENSE.md`:** bc-csharp's `LICENSE.md` verbatim.
   - **`THIRD-PARTY-NOTICES.txt`:** the BC MIT text, plus any non-BC licence header found in the closure.
     - To find them, look for `Permission is hereby granted`/`Licensed under`, excluding the standard BC header, and
       review by hand.
     - Blake2Fast only if present; the reproduced closure has none.
     - turboHTTP merges this file into its own (#5).
   - **`STRIP_INFO.md`:** BASE, ROOTS_SHA, the cut list, per-directory counts and the smoke results. Also the shadow
     diff `git diff OLDBASE..NEWBASE` for `security/PublicKeyFactory.cs`, `x509/X509SignatureUtil.cs`,
     `security/MacUtilities.cs` and `crypto/modes/GCMBlockCipher.cs`. Shadow paths are checked against `git ls-files` to
catch case errors.
7. **Hand over** `strip/out/` (#141). turboHTTP runs:
   `rsync -a --delete --exclude='/*.asmdef' --exclude='/*.asmdef.meta' strip/out/Lib/ <turboHTTP>/Runtime/Transport/BouncyCastle/Lib/`.
   This repo never writes into turboHTTP.

## 6. Order of work and definition of done

1. **Bootstrap** (possible now): `strip.sh --report` with the provisional define sets. Write E1–E14 and finish the
   tool (lookup order, extension index).
2. **Defines:** #141 supplies `unity-defines.txt` and the decision record (A–G). Commit both, apply any E13 guard
   fixes, run enforce mode, set `budget.txt`, run the smoke suite.
3. **Hand over.** turboHTTP does #140 and #143 first: the gate depends on #140, and #141 is blocked by #143. Then
   #141 (sync + gate), then #142.
4. **Re-strip** when a roots file or `roots-extra.cs` changes, or on a bump.

- **Strip done:** smoke suite passes here **and** the #141 gate passes on output from the recorded `BASE` and
  `ROOTS_SHA`.
- **BC production-ready:** strip done **and** #33, #34, #36 and #142 are closed. #113 (the negative TLS suite)
  validates it. This is not owned by this repo.
- **Bump cadence:** at every upstream release or BC security advisory, and at least quarterly. Update `BASE`, rebase
  with rerere, run `strip.sh`, review the shadow diff, hand over.

## 7. Alternative in reserve

Use the official DLL, renamed and internalised with Cecil. Switch when a bump costs more than about 1 day of edge-cut
conflicts, or when a needed upstream fix can't be taken quickly. With the DLL:
- E1, E3 and E4 become consumer subclasses (`BcTlsCrypto` has about 32 overridable `Has*`/`Create*` methods).
- E7 becomes property settings (mind the key rewrite).
- E5's EC check moves to `NotifyServerCertificate`.
- Size control is lost.

## 8. turboHTTP issues (owned by the turboHTTP agent)

| Need | Issue |
|---|---|
| Auto fails closed | #34 |
| Chain validation + RFC 6125 hostname (decision A) | #33 |
| SNI IDN / no IP literal | #46 |
| Client config: explicit suites, OCSP null, handshake timeout + socket `ReceiveTimeout`, close-notify truncation | #142 (timeout AC needs #141) |
| Notices + upstream record | #5 (+ #4) |
| link.xml honoured; narrow BC preserve; size | #8 |
| Own asmdef; delete RepackageBouncyCastle; assembly-qualified names | #143 |
| BC tests: Ignored = failure; device-run preserves | #140 |
| Defines + decision record, sync, gate, mobile GCM/AES throughput | #141 |
| BC TlsStream duplex | #36 |
| Negative TLS suite | #113 |

## 9. Unverified

- Unity define sets; UPM `link.xml`; whether Unity Mono's `X509Chain` handles ECDSA and name constraints (decision A).
- The patched closure size.
- Mobile figures: Miller-Rabin cost, ASN.1 stack depth, AES/GCM throughput.

## Appendix A — TurboVerifierFactory (deferred; only if BC-side certificate verification is chosen later)

An `IVerifierFactory` that dispatches by OID to upstream signer classes and returns `DefaultVerifierCalculator`.

| Algorithm | Construction |
|---|---|
| sha{256,384,512}WithRSAEncryption `1.2.840.113549.1.1.{11,12,13}`, NULL/absent params | `new RsaDigestSigner(digest, digestOid)` |
| id-RSASSA-PSS `…1.1.10` | Hash ∈ SHA-256/384/512. MGF = `id-mgf1` with the same hash. **saltLength == hLen** checked before construction (blocks the `new byte[saltLen]` DoS at `PssSigner.cs:121-124`). Trailer 1 → `PssSigner.TrailerImplicit`. Construct `new PssSigner(new RsaBlindedEngine(), d, d, hLen, TrailerImplicit)` |
| ecdsa-with-SHA{256,384,512} `1.2.840.10045.4.3.{2,3,4}` | `new DsaDigestSigner(new ECDsaSigner(), digest)`, strict DER |
| anything else | `CertificateException` |

It also rejects private keys and maps a key/algorithm mismatch to false. Add a differential test against upstream
`SignerUtilities` over bc-test-data `pkix/cert` and `PKITS/certs`, with an expected-divergence list (PSS non-default
salt, SHA-1, Ed25519).
