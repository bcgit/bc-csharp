# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Overview

Bouncy Castle for .NET — a cryptography library providing primitives, protocols (CMS, OpenPGP, (D)TLS, TSP, X.509), and NIST PQC algorithms (ML-DSA, ML-KEM, SLH-DSA, Falcon, etc.). This is the **non-FIPS** source tree; the FIPS distribution is separate.

Root namespace: `Org.BouncyCastle`. NuGet package id: `BouncyCastle.Cryptography`.

Security issues: see [SECURITY.md](SECURITY.md) — report privately to feedback-crypto@bouncycastle.org rather than filing a public issue.

## Solution layout

Two projects, both under [crypto/](crypto/):

- [crypto/src/BouncyCastle.Crypto.csproj](crypto/src/BouncyCastle.Crypto.csproj) — main library. Multi-targets `net6.0;netstandard2.0;net461`. AOT-compatible on net7+. Signed with [BouncyCastle.NET.snk](BouncyCastle.NET.snk) — do not bypass signing or modify the key. Versioning is driven by Nerdbank.GitVersioning from [version.json](version.json); see **API stability and versioning**.
- [crypto/test/BouncyCastle.Crypto.Tests.csproj](crypto/test/BouncyCastle.Crypto.Tests.csproj) — NUnit 3 test project. Multi-targets `net6.0;netcoreapp3.1;net472;net461`. Small/inline test data lives in [crypto/test/data/](crypto/test/data/) and is embedded as resources.

Source under [crypto/src/](crypto/src/) is grouped by domain (`crypto/`, `math/`, `asn1/`, `pqc/`, `tls/`, `openpgp/`, `cms/`, `pkix/`, `x509/`, `security/`, `util/`, …); tests mirror the layout under [crypto/test/src/](crypto/test/src/). Two things the tree doesn't tell you: the `*Utilities` classes in [crypto/src/security/](crypto/src/security/) (`CipherUtilities`, `DigestUtilities`, `PrivateKeyFactory`, …) are the public surface most consumers use, and [crypto/src/pqc/](crypto/src/pqc/) is flagged EXPERIMENTAL in the README.

Build configurations: `Debug`, `Release`, `Publish` (Publish adds deterministic build + assembly signing via [signfile.bat](signfile.bat)).

**Bulk test data lives in a separate repository.** Clone https://github.com/bcgit/bc-test-data.git, conventionally as a sibling of this repo (`../bc-test-data`). `SimpleTest.FindTestDataPath` ([SimpleTest.cs](crypto/test/src/util/test/SimpleTest.cs)) walks up from the working directory until it finds an ancestor containing a `bc-test-data` folder; tests that need it throw `DirectoryNotFoundException` if it is missing.

**Where to put new test vectors / sample files** — no fixed rule. Propose a location (embedded in [crypto/test/data/](crypto/test/data/) vs. the external `bc-test-data` repo) and let the user decide; size, sensitivity, and likely reuse by the Java/FIPS sister projects all factor in.

## Build / test commands

```powershell
dotnet build crypto/src/BouncyCastle.Crypto.csproj
dotnet build BouncyCastle.sln
dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj
dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj --filter "FullyQualifiedName~ChaCha20Poly1305Test"
```

CI ([.gitlab-ci.yml](.gitlab-ci.yml)) runs tests on net461, net472, netcoreapp3.1, and net6.0. Code that compiles on one TFM can fail on another (Span APIs, intrinsics availability, `System.Numerics` differences), so verify with at least one .NET Framework TFM when touching the `#if` switches.

For hardware-intrinsics code (anything under [crypto/src/runtime/intrinsics/](crypto/src/runtime/intrinsics/), any `*_X86.cs` file, or code using `System.Runtime.Intrinsics`), use the **intrinsics-testing** skill. ISA detection must go through the `Org.BouncyCastle.Runtime.Intrinsics` wrappers, and the skill has the commands for re-running tests with specific instruction sets disabled.

### Mid-session verification

Fast turnaround beats exhaustive coverage during an iterative session: build only the affected project(s), run only the plausibly impacted fixtures via `--filter` on a single TFM (net6.0 unless the change is TFM-specific), and widen only when the change spans broad areas (core utilities, ASN.1 base types, anything in `crypto/src/util/`). The final pre-push run across the full TFM matrix is the user's responsibility — don't block on it.

## Conventions

- **Multi-TFM source.** Span and intrinsics code is guarded by `#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER` and `#if NETCOREAPP3_0_OR_GREATER` respectively (see [AesEngine_X86.cs](crypto/src/crypto/engines/AesEngine_X86.cs), [ChaCha7539Engine.cs](crypto/src/crypto/engines/ChaCha7539Engine.cs)). The legacy path under `#else` must remain functionally equivalent.
- **Span overloads for new public APIs.** On hot paths (cipher / digest / MAC `Update`/`DoFinal`, math primitives, parsing fast paths), add a `ReadOnlySpan<byte>` / `Span<byte>` overload alongside any new `byte[]`-shaped public method, under the same guard. For non-hot-path APIs, ask first — they're only worth the maintenance when allocation/copy avoidance pays off.
- **Tests.** Write new tests as plain NUnit (`[TestFixture]` / `[Test]` / `Assert.That`). Many existing fixtures extend `SimpleTest` ([SimpleTest.cs](crypto/test/src/util/test/SimpleTest.cs)); that base class is legacy tooling — don't extend it in new code, but follow the local convention when editing an existing subclass.
- **Testing internals.** The test assembly is a friend of the library (`InternalsVisibleTo` in [AssemblyInfo.cs](crypto/src/AssemblyInfo.cs)). Use it only when a behaviour has no good test at the public surface; prefer public-API tests, and don't widen `private` to `internal` just for testability unless a public-API test is genuinely impractical.
- **Constant-time discipline.** In new code, treat any branch, table index, or early exit on secret material as a defect; use [`Arrays.FixedTimeEquals`](crypto/src/util/Arrays.cs), bitwise selects, and the other CT helpers, and call out side-channel risks proactively. If told a particular leak is acceptable, propose an inline comment recording the choice. In existing code that isn't the focus of review, follow the surrounding discipline — its patterns reflect deliberate choices — and don't proactively rewrite long-established patterns.
- **Wiping secrets.** Use [`Arrays.ZeroMemory`](crypto/src/util/Arrays.cs) rather than `Array.Clear` / `Span.Clear` / hand-written loops; it delegates to `CryptographicOperations.ZeroMemory` where available, which the JIT cannot elide as a dead store.
- **PQC code style.** `crypto/src/pqc/` deliberately tracks the upstream reference C and is less idiomatic than the rest of the library — keep ports close to reference rather than refactoring for style.
- **bc-java.** [bc-java](https://github.com/bcgit/bc-java) shares heritage and is worth consulting when an algorithm or API already exists there, but parity is loose: diverge freely for idiomatic C#, performance (Spans, intrinsics, ref structs), or .NET features. No obligation to keep in lockstep or to flag parity for routine work.

## API stability and versioning

The library follows Semantic Versioning ([version.json](version.json)); the current series is **v2.x**. `assemblyVersion.precision` is `"major"`, so the assembly version is fixed across the whole series and strong-named references must keep resolving — **binary as well as source compatibility is a hard requirement** within v2.x.

- Only additive changes in minor/patch releases: prefer **adding an overload** over changing an existing public signature.
- **Deprecate, don't remove.** Mark superseded public API `[Obsolete("Use 'Replacement' instead")]` and keep it working (e.g. [SignerInformation.cs](crypto/src/cms/SignerInformation.cs#L132)). Removal waits for a major bump.
- **Record deferred breaks with `// TODO[api]`.** When a change would improve the API but can't ship until a break is permitted, leave a `// TODO[api] <what to do>` comment at the site (e.g. [SignerUtilities.cs](crypto/src/security/SignerUtilities.cs#L954), [X509Utilities.cs](crypto/src/x509/X509Utilities.cs#L212)) — this is how the next major's work list accumulates.
- **When a change seems to require a break, flag it** rather than proceeding; the maintainer decides whether to find a compatible path or defer it.

## Style

Follow [.editorconfig](.editorconfig) (4-space indent, Allman braces, modifier order, etc.). Beyond what it encodes:

- **Line length: 120 characters max** for new code and comments. Plenty of older code exceeds this — leave it alone unless you're otherwise editing it.
- **Always brace control statements.** The only exceptions: an `if` with no `else` whose body is a single-line `return` or `throw`, and a `lock` with a single-line `return` or `throw` body.
- **Prefer expression-bodied methods** when the whole declaration fits on one or two lines (signature on line one, expression on a single indented second line). Use a block body when the expression would need wrapping or the body is more than a single expression.
- Keep patches focused ([CONTRIBUTING.md](CONTRIBUTING.md)): don't reformat unrelated code or whitespace in the same change.

**Whitespace cleanup workflow.** The tree has accumulated whitespace inconsistencies (mixed tabs/spaces, trailing whitespace, missing final newlines). When about to edit a file with such issues, first **propose a separate whitespace-only commit** normalizing the **entire file** to .editorconfig, then apply the substantive edits on top, so the functional change stays reviewable.

**Commit messages.** Match the existing log: short imperative summary (~50–70 chars), no conventional-commit prefix. Add a body only when the *why* isn't obvious from the diff (performance motivation with rough numbers, a referenced issue, a behavioral change a reader might miss, a non-trivial design choice). Example log: "Refactor (X)ChaCha20 code", "Add XChaCha20 and XChaCha20-Poly1305 (issue #624)".

**Merges.** Never create a non-fast-forward merge commit (e.g. `git merge` of a diverged branch, `git pull` without `--ff-only`) without explicit direction or confirmation from the user.
