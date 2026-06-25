# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Bouncy Castle for .NET — a cryptography library providing primitives, protocols (CMS, OpenPGP, (D)TLS, TSP, X.509), and NIST PQC algorithms (ML-DSA, ML-KEM, SLH-DSA, Falcon, etc.). This is the **non-FIPS** source tree; the FIPS distribution is separate.

Root namespace: `Org.BouncyCastle`. NuGet package id: `BouncyCastle.Cryptography`.

## Solution layout

Two projects, both under [crypto/](crypto/):

- [crypto/src/BouncyCastle.Crypto.csproj](crypto/src/BouncyCastle.Crypto.csproj) — main library. Multi-targets `net6.0;netstandard2.0;net461`. AOT-compatible on net7+. Signed with [BouncyCastle.NET.snk](BouncyCastle.NET.snk). Versioning is driven by Nerdbank.GitVersioning from [version.json](version.json) — see **API stability and versioning** for the compatibility contract this implies.
- [crypto/test/BouncyCastle.Crypto.Tests.csproj](crypto/test/BouncyCastle.Crypto.Tests.csproj) — NUnit 3 test project. Multi-targets `net6.0;netcoreapp3.1;net472;net461`. Small/inline test data lives in [crypto/test/data/](crypto/test/data/) and is embedded as resources.

**Bulk test data lives in a separate repository.** Clone https://github.com/bcgit/bc-test-data.git — the convention is to put it as a sibling of this repo (`../bc-test-data`), but `SimpleTest.FindTestDataPath` ([SimpleTest.cs](crypto/test/src/util/test/SimpleTest.cs)) walks up from the current working directory until it finds any ancestor containing a folder named `bc-test-data`, so any location on that path works. Tests that depend on it throw `DirectoryNotFoundException` if it is missing.

**Where to put new test vectors / sample files** — no fixed rule. Ask before placing them: propose a location (inline in [crypto/test/data/](crypto/test/data/) for embedded resources vs. the external `bc-test-data` repo) and let the user decide. Size, sensitivity, and whether the vectors are likely to be reused by Java/FIPS sister projects all factor in.

Three build configurations: `Debug`, `Release`, `Publish` (Publish adds deterministic build + assembly signing via [signfile.bat](signfile.bat)).

## Build / test commands

```powershell
# Build the library only
dotnet build crypto/src/BouncyCastle.Crypto.csproj

# Build everything via the solution
dotnet build BouncyCastle.sln

# Run all tests against a specific TFM (CI runs net461, net472, netcoreapp3.1, net6.0)
dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj

# Run a single test fixture
dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj --filter "FullyQualifiedName~ChaCha20Poly1305Test"

# Run a single test method
dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj --filter "FullyQualifiedName=Org.BouncyCastle.Crypto.Tests.ChaCha20Poly1305Test.TestVectors"
```

When writing, modifying, or verifying code that uses hardware intrinsics (anything under [crypto/src/runtime/intrinsics/](crypto/src/runtime/intrinsics/), any `*_X86.cs` file, or code using `System.Runtime.Intrinsics`), see the **intrinsics-testing** skill. It covers the project rule that ISA detection must go through the `Org.BouncyCastle.Runtime.Intrinsics` wrappers (not direct `IsSupported` checks), the planned move toward limited ISA profiles, and the commands to re-run tests with specific instruction sets disabled.

### Mid-session verification expectations

Fast turnaround matters more than exhaustive coverage during an iterative session. Default to:

- Building only the project(s) actually affected by the change (usually `crypto/src/BouncyCastle.Crypto.csproj`, and the test project if tests changed).
- Running just the test fixtures plausibly impacted, via `--filter`, on a single TFM (net6.0 unless the change is TFM-specific).
- Falling back to a wider build/test run only when the change spans broad areas (e.g. core utilities, ASN.1 base types, anything in `crypto/src/util/`).

The final pre-push verification across the full TFM matrix is the user's responsibility — don't block on it.

## Source tree

All source under [crypto/src/](crypto/src/), grouped by domain:

- [crypto/src/crypto/](crypto/src/crypto/) — low-level primitives: `engines/` (block/stream ciphers), `digests/`, `macs/`, `modes/` (CBC, GCM, CCM, …), `paddings/`, `signers/`, `generators/`, `agreement/`, `kems/`, `prng/`, `parameters/`, `tls/`.
- [crypto/src/math/](crypto/src/math/) — `BigInteger`, EC math (`ec/custom/` per-curve specialized impls, `ec/rfc7748/` X25519/X448, `ec/rfc8032/` Ed25519/Ed448), finite-field code, multipliers.
- [crypto/src/asn1/](crypto/src/asn1/) — ASN.1 encoders/decoders + per-standard OID/structure modules (pkcs, x509, cms, …).
- [crypto/src/pqc/](crypto/src/pqc/) — Post-quantum algorithms (`crystals/` for ML-KEM/ML-DSA, plus falcon, bike, cmce, frodo, hqc, ntru, picnic, saber, sphincsplus, lms). These are flagged EXPERIMENTAL in the README.
- [crypto/src/tls/](crypto/src/tls/) — TLS/DTLS protocol implementation.
- [crypto/src/openpgp/](crypto/src/openpgp/), [crypto/src/cms/](crypto/src/cms/), [crypto/src/pkix/](crypto/src/pkix/), [crypto/src/pkcs/](crypto/src/pkcs/), [crypto/src/x509/](crypto/src/x509/), [crypto/src/tsp/](crypto/src/tsp/), [crypto/src/cmp/](crypto/src/cmp/), [crypto/src/crmf/](crypto/src/crmf/), [crypto/src/ocsp/](crypto/src/ocsp/), [crypto/src/openssl/](crypto/src/openssl/) — higher-level protocol/format packages.
- [crypto/src/security/](crypto/src/security/) — `*Utilities` factory-style entry points (`CipherUtilities`, `DigestUtilities`, `MacUtilities`, `PrivateKeyFactory`, `PublicKeyFactory`, `SecureRandom`, …). These are the typical public surface; callers look up algorithms by name/OID.
- [crypto/src/util/](crypto/src/util/) — arrays/bytes/ints/longs helpers, encoders (Hex/Base64), I/O streams, bundled bzip2/zlib.

Tests mirror the same layout under [crypto/test/src/](crypto/test/src/).

## Architectural conventions

- **Public API surface.** Most consumers go through the `*Utilities` classes in [crypto/src/security/](crypto/src/security/) (e.g. `CipherUtilities.GetCipher("AES/GCM/NoPadding")`, `DigestUtilities.GetDigest("SHA-256")`). Direct construction of engine classes is also supported and is what most internal code does.
- **Cipher composition.** Stream/AEAD ciphers implement `IStreamCipher` / `IAeadCipher`; block ciphers (`IBlockCipher`) are wrapped by a mode (`modes/`) and padding (`paddings/`) and surfaced via `BufferedBlockCipher` / `BufferedAeadBlockCipher`.
- **Multi-TFM source.** Span-based and intrinsics overloads are guarded by `#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER` (Spans) and `#if NETCOREAPP3_0_OR_GREATER` (`System.Runtime.Intrinsics.*` for AES-NI, SSE2, AVX2, etc. — see [AesEngine_X86.cs](crypto/src/crypto/engines/AesEngine_X86.cs), [ChaCha7539Engine.cs](crypto/src/crypto/engines/ChaCha7539Engine.cs)). When editing engines, the legacy code path under `#else` must remain functionally equivalent.
- **Test framework.** Write new tests as plain NUnit (`[TestFixture]` / `[Test]` with `Assert.That(...)`, `Assert.AreEqual`, etc.). Many existing fixtures still extend `SimpleTest` ([crypto/test/src/util/test/SimpleTest.cs](crypto/test/src/util/test/SimpleTest.cs)) and use its `IsTrue` / `IsEquals` / `Fail` helpers — that base class is **legacy tooling** kept for the older suite; do not extend it in new code. When editing an existing `SimpleTest` subclass, follow the local convention rather than rewriting it.
- **Constant-time / side-channel discipline.**
  - **In new code**, default to strict: assume any branch, table index, or early exit on secret material is a defect. Reach for [`Arrays.FixedTimeEquals`](crypto/src/util/Arrays.cs), bitwise selects, and other CT helpers, and call out side-channel risks proactively. If you're explicitly told a particular construction is acceptable despite the leak, propose an inline comment recording the deliberate choice.
  - **In existing code that isn't the focus of review**, follow the surrounding discipline — the patterns there reflect deliberate choices about which side-channels the algorithm defends against. Flag obvious regressions you introduce; don't proactively rewrite long-established patterns.
- **Wiping secret buffers.** Prefer [`Arrays.ZeroMemory`](crypto/src/util/Arrays.cs) over `Array.Clear`, `Span.Clear`, or hand-written zero loops when wiping key material, intermediate state, or other secret-bearing buffers. `ZeroMemory` delegates to `CryptographicOperations.ZeroMemory` on TFMs that have it, which the JIT is not allowed to elide as a dead store — plain `Clear` calls can be eliminated and leave the secret in memory.
- **`Span<byte>` overloads for new public APIs.** On hot paths (cipher / digest / MAC `Update`/`DoFinal`, math primitives, parsing fast paths), add a `ReadOnlySpan<byte>` / `Span<byte>` overload alongside any new `byte[]`-shaped public method, guarded by the existing `#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER`. For non-hot-path APIs (configuration, builder-style methods, rarely-called helpers), ask before adding Span variants — they're worth the maintenance only when allocation/copy avoidance pays off.
- **PQC code style.** `crypto/src/pqc/` largely follows the upstream reference C and is intentionally less idiomatic than the rest of the library — keep ports close to reference rather than refactoring for style.
- **Relationship to Java Bouncy Castle.** [bc-java](https://github.com/bcgit/bc-java) shares heritage and many design choices, and it's worth consulting when an algorithm or API is already implemented there. But parity is **loose**: this codebase is free to diverge for idiomatic C# reasons, for performance (Spans, intrinsics, ref structs), or to take advantage of .NET features. No obligation to keep changes in lockstep with bc-java or to flag upstream parity for routine work.

## API stability and versioning

The library follows **Semantic Versioning 2.0.0** ([version.json](version.json) →
`nugetPackageVersion.semVer: 2`). The current series is **v2.x**.

**Backward compatibility is maintained within a major version sequence.** Within v2.x, changes must not
break source or binary compatibility for existing public API consumers. `assemblyVersion.precision` is
`"major"`, so the assembly version stays fixed across the whole major series — strong-named references must
keep resolving, which makes binary compatibility a hard requirement, not a nicety.

- **Allowed in a minor/patch release (additive):** new public types, members, and overloads, and new
  opt-in behavior. Prefer **adding an overload** over changing an existing public signature.
- **Reserved for the next major (breaking):** removing or renaming public types/members, changing
  signatures or return types, tightening accessibility, or behavioral changes existing callers would
  observe as a break.
- **Deprecate, don't remove.** Mark superseded public API with `[Obsolete("Use 'Replacement' instead")]`
  and keep it working — matching the existing convention (e.g.
  [SignerInformation.cs](crypto/src/cms/SignerInformation.cs#L132)). Actual removal waits for a major bump.
- **Record deferred breaks with a `// TODO[api]` comment.** When you spot a change that would improve the
  API but can't ship until a break is permitted (a rename, making a type static, removing a legacy code
  path, dropping an obsoleted member), leave a `// TODO[api] <what to do>` comment at the site rather than
  doing it now. This is an established marker across the tree (e.g.
  [SignerUtilities.cs](crypto/src/security/SignerUtilities.cs#L954),
  [X509Utilities.cs](crypto/src/x509/X509Utilities.cs#L212)) — it's how the next major's work list is
  accumulated in place.
- **When a change seems to require a break, flag it** rather than proceeding — the maintainer decides
  whether to find a compatible path or defer it (with a `// TODO[api]` note) to the next major.

## Style (from [.editorconfig](.editorconfig))

- 4-space indent for `*.cs`; 2-space for XML/project files.
- **Line length: 120 characters max** for new code and comments. There is plenty of older code that exceeds this — leave it alone when not otherwise editing it, but don't introduce new violations.
- Allman braces (`csharp_new_line_before_open_brace = all`), and new lines before `else`/`catch`/`finally`.
- **Always brace control statements** (`if`/`else`/`for`/`foreach`/`while`/`do`/`using`/`lock`). The only exceptions:
  - an `if` with no matching `else` whose body is a single-line `return` or `throw` may omit the braces (e.g. `if (x == null) throw new ArgumentNullException(nameof(x));`).
  - a `lock` whose body is a single-line `return` or `throw` may likewise omit the braces.
- **Prefer expression-bodied methods** when the whole declaration fits neatly on one or two lines — either `T Method(args) => expr;` on a single line, or the signature on line one with the expression on a single indented second line. Fall back to a regular block body when the expression would itself need wrapping, or when the body is more than a single expression.
- Modifier order: `public,private,protected,internal,file,static,extern,new,virtual,abstract,sealed,override,readonly,unsafe,required,volatile,async`.
- UTF-8 (no BOM) for project files; CRLF for `*.bat`/`*.cmd`.

Per [CONTRIBUTING.md](CONTRIBUTING.md): keep patches focused — do not reformat unrelated code or whitespace in the same change.

**Whitespace cleanup workflow.** The project has accumulated whitespace inconsistencies (mixed tabs/spaces, trailing whitespace, missing final newlines, lines that don't conform to [.editorconfig](.editorconfig)) that we'd like to clean up over time. Whenever you're about to edit a file that has such issues, first **propose a separate whitespace-only cleanup commit** that normalizes the **entire file** to the .editorconfig rules — then apply the substantive edits on top. Keep the two commits distinct so the functional change stays reviewable and the whitespace fix lands mechanically across the whole file at once.

**Commit messages.** Match the existing log: short imperative summary (~50–70 chars), no conventional-commit prefix. Add an explanatory body when the *why* isn't obvious from the diff — e.g. performance motivation with rough numbers, a referenced issue, a behavioral change a reader might miss, or a non-trivial design choice. Routine refactors, renames, and one-line fixes don't need a body. Example log: "Refactor (X)ChaCha20 code", "ChaCha20 performance and intrinsics improvements", "Add XChaCha20 and XChaCha20-Poly1305 (issue #624)".

## Notes

- Do not bypass assembly signing or modify [BouncyCastle.NET.snk](BouncyCastle.NET.snk).
- The CI matrix ([.gitlab-ci.yml](.gitlab-ci.yml)) runs tests on net461, net472, netcoreapp3.1, and net6.0 — changes that compile on one TFM can fail on others (Span APIs, intrinsics availability, `System.Numerics` differences), so verify with at least one .NET Framework TFM when touching the `#if` switches.
- Security issues: see [SECURITY.md](SECURITY.md) — report privately to feedback-crypto@bouncycastle.org rather than filing a public issue.
