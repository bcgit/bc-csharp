---
name: intrinsics-testing
description: Use when the user is writing, modifying, reviewing, or verifying hardware-intrinsics code in bc-csharp — i.e. anything under crypto/src/runtime/intrinsics/, any *_X86.cs file, or any other code that uses System.Runtime.Intrinsics. Covers the project rule that ISA detection must go through the Org.BouncyCastle.Runtime.Intrinsics wrappers (not direct System.Runtime.Intrinsics.X86.*.IsSupported checks), commands to re-run tests with specific instruction sets disabled via DOTNET_Enable*/COMPlus_Enable* env vars so scalar and lower-ISA fallback codepaths get exercised, and the planned trajectory toward a limited set of supported ISA profiles.
---

# Working with hardware intrinsics

## Always go through the BC wrappers for ISA detection

**Rule:** when gating an intrinsic codepath on the availability of a hardware ISA, use the wrappers under [`Org.BouncyCastle.Runtime.Intrinsics`](../../../crypto/src/runtime/intrinsics/) — never call `System.Runtime.Intrinsics.X86.*.IsSupported` (or `ArmBase.*.IsSupported`, etc.) directly from engine / digest / math code.

Use:

```csharp
if (Org.BouncyCastle.Runtime.Intrinsics.X86.Aes.IsEnabled)
{
    // AES-NI implementation
}
```

Not:

```csharp
#if NETCOREAPP3_0_OR_GREATER
if (System.Runtime.Intrinsics.X86.Aes.IsSupported)   // ❌ direct check
{
    // ...
}
#endif
```

Why it matters:

- **Single point of indirection.** All gates can be flipped globally — for testing, for opt-out scenarios, or for the profile-based gating described below — without touching every callsite.
- **TFM uniformity.** The wrappers compile cleanly on TFMs that don't have `System.Runtime.Intrinsics` at all (`net461`, `net472`, `netstandard2.0`) by hard-coding `IsEnabled => false`. Callers don't need their own `#if NETCOREAPP3_0_OR_GREATER` guard around the check itself — only around the body that uses the intrinsics types.
- **Forward compatibility.** See "Limited ISA profiles" below.

### The wrapper set is intentionally narrow

The wrappers don't aim to mirror the whole BCL surface — they only cover ISAs we actually use somewhere in the codebase. Today that's just `Aes`, `Avx2`, `Bmi1`, `Bmi2`, `Pclmulqdq`, `Sse2`, `Sse41`, `Ssse3` (under [crypto/src/runtime/intrinsics/x86/](../../../crypto/src/runtime/intrinsics/x86/)). Anything else (e.g. `Avx`, `Avx512F`, `Sse42`, ARM `AdvSimd`, ARM `Crypto`) has no wrapper because nothing in BC has needed one yet.

**When introducing a new intrinsic codepath that depends on an ISA without an existing wrapper, add the wrapper first.** Pattern, mirroring the existing files:

```csharp
namespace Org.BouncyCastle.Runtime.Intrinsics.X86
{
    internal static class Avx512F
    {
#if NETCOREAPP3_0_OR_GREATER
        internal static bool IsEnabled => System.Runtime.Intrinsics.X86.Avx512F.IsSupported;
#else
        internal static bool IsEnabled => false;
#endif
    }
}
```

Then have the new engine/digest/math code consume `Avx512F.IsEnabled` rather than the BCL `IsSupported` directly. This keeps every gate routable through the same future profile mechanism.

Don't add wrappers speculatively for ISAs that no code uses yet — they'd just be dead surface area and would muddy the "what does BC actually exercise" picture. Add them on demand, in the same PR as the first consumer.

## Limited ISA profiles (planned direction)

The cross-product of individual ISA toggles is too large to test exhaustively. The planned evolution is to support only a small, enumerated set of **ISA profiles** (combinations of available ISAs that ship together — e.g. "scalar only", "SSE2+AES+PCLMULQDQ", "AVX2+AES+PCLMULQDQ+BMI2", etc.) so that complete coverage is actually achievable.

Implications for code being written today:

- Going through the wrappers (rule above) is what makes the eventual profile gating possible — the wrappers will be where profile selection plugs in.
- Don't introduce new ISA combinations that wouldn't fit a small profile set. If you find yourself wanting a check like "AVX2 but no BMI2," step back: that combination probably isn't on any plausible profile list and you're multiplying the test matrix for a configuration that won't actually ship.
- New intrinsic codepaths should be tractable to fully exercise via the testing approach below; if a path is reachable only under an exotic ISA mix, that's a smell.

## Testing fallback paths

When a change touches intrinsics code, the default `dotnet test` run only exercises one ISA path — whichever the host CPU supports. To verify the fallbacks, re-run the suite with specific instruction sets disabled via the .NET runtime's `Enable*` toggles. The wrappers honor these toggles automatically because their `IsEnabled` properties delegate to `IsSupported`, which is what the runtime flag affects.

### When this applies

The toggles only affect TFMs with `System.Runtime.Intrinsics` available — i.e. `net6.0` (and `netcoreapp3.1` via the `COMPlus_` prefix). The `.NET Framework` targets (`net461`, `net472`) don't compile the intrinsics paths at all (`#if NETCOREAPP3_0_OR_GREATER` guards them out), so there's nothing to toggle there.

Code locations likely affected by ISA toggles:

- [crypto/src/runtime/intrinsics/](../../../crypto/src/runtime/intrinsics/) — the `IsEnabled` wrappers themselves.
- `*_X86.cs` files (e.g. [AesEngine_X86.cs](../../../crypto/src/crypto/engines/AesEngine_X86.cs), [Blake2b_X86.cs](../../../crypto/src/crypto/digests/Blake2b_X86.cs), [Haraka512_X86.cs](../../../crypto/src/crypto/digests/Haraka512_X86.cs)).
- Engines/modes/math files with inline `#if NETCOREAPP3_0_OR_GREATER` blocks that go through the wrappers (e.g. [ChaCha7539Engine.cs](../../../crypto/src/crypto/engines/ChaCha7539Engine.cs), [GCMBlockCipher.cs](../../../crypto/src/crypto/modes/GCMBlockCipher.cs), [Nat256.cs](../../../crypto/src/math/raw/Nat256.cs)). Any callsite that bypasses the wrappers (see the rule above) is itself a bug — fix the wrapper indirection rather than working around it.

### Env-var prefix

- `.NET 5+` (which includes net6.0): `DOTNET_Enable*=0`
- `netcoreapp3.1`: `COMPlus_Enable*=0`

Setting the value to `0` disables that instruction set; the runtime will then report `IsSupported = false` for it and any others that depend on it. Because BC's `IsEnabled` wrappers delegate to `IsSupported`, the toggles propagate transparently to all gated codepaths.

### PowerShell variants

Default (best-available) baseline:

```powershell
dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj
```

Disable AVX2 (forces the SSE2/SSSE3/SSE41 paths):

```powershell
$env:DOTNET_EnableAVX2=0
dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj
Remove-Item env:DOTNET_EnableAVX2
```

Disable AES-NI + PCLMULQDQ (forces software AES and software GHASH):

```powershell
$env:DOTNET_EnableAES=0
$env:DOTNET_EnablePCLMULQDQ=0
dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj
Remove-Item env:DOTNET_EnableAES
Remove-Item env:DOTNET_EnablePCLMULQDQ
```

Disable all hardware intrinsics in one shot (forces the pure-managed scalar paths):

```powershell
$env:DOTNET_EnableHWIntrinsic=0
dotnet test --framework net6.0 crypto/test/BouncyCastle.Crypto.Tests.csproj
Remove-Item env:DOTNET_EnableHWIntrinsic
```

For `netcoreapp3.1`, swap `DOTNET_` for `COMPlus_`:

```powershell
$env:COMPlus_EnableAVX2=0
dotnet test --framework netcoreapp3.1 crypto/test/BouncyCastle.Crypto.Tests.csproj
Remove-Item env:COMPlus_EnableAVX2
```

### Full list of toggles used in this codebase

`DOTNET_EnableAES`, `DOTNET_EnableAVX`, `DOTNET_EnableAVX2`, `DOTNET_EnableBMI1`, `DOTNET_EnableBMI2`, `DOTNET_EnablePCLMULQDQ`, `DOTNET_EnableSSE2`, `DOTNET_EnableSSE41`, `DOTNET_EnableSSSE3`, plus the catch-all `DOTNET_EnableHWIntrinsic`.

### Caveats

- **`DOTNET_EnableSSE2=0` is ignored on x64.** The .NET runtime treats SSE2 as part of the x64 ABI, so the toggle is honored only on 32-bit hosts. To actually test without SSE2, run with `dotnet test -a x86 ...` (and pick a TFM that supports x86, e.g. `netcoreapp3.1` or `net6.0`).
- Pick targeted combinations rather than running the full cross-product — a few well-chosen disables (highest ISA off, AES-NI off, all-off) usually cover the meaningful fallback shapes for a given change. Once the limited-profiles model lands, the targeted set will be the profile list itself.
- Failed assertions under a disabled ISA usually mean the fallback path diverged from the intrinsic path; the failing test name plus the disabled toggle identifies the regression area.

### When *not* to run these

Don't run the variant suites for changes that don't touch intrinsics code or anything they call into. The default test run is sufficient for non-intrinsics work, and the variant runs add real time to the loop.
