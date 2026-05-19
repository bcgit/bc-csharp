using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.BinPoly
{
    internal abstract partial class BinPolyMulBase
    {
        // Pentanomial reduction by x^n + x^k3 + x^k2 + x^k1 + 1 with 0 < k1 < k2 < k3 < n. The
        // factory selects one of several specialized implementations based on (n, k1, k2, k3);
        // each has a streamlined Reduce body for its case. Each bit at position p >= n folds
        // via the "+1" tap to position (p - n) and via the "+x^ki" taps to positions
        // (p - n + ki). n need not be odd; the word-at-a-time variants require a partial top limb
        // ((n & 63) != 0). The factory routes word-aligned n ((n & 63) == 0) to E (the word-
        // aligned analogue of B, when all (k_i & 63) != 0 and n - k3 >= 64) or otherwise to the
        // bitwise reducer C.
        //
        // Sub-case naming: A<N> denotes a fully-unrolled size-K reducer that loads N limbs of
        // tt. Each polynomial size K = w_n + 1 has a paired (slack, non-slack) flavour: slack
        // uses (2K - 1) limbs (the topmost limb tt[2K - 1] is zero by the IReduce contract
        // for low-enough n), and non-slack uses 2K. The A family (all k_i < 64) has A3 / A4
        // (size 2), A5 / A6 (size 3), A7 / A8 (size 4); plain A handles w_n >= 4 (n >= 257)
        // via a non-unrolled word-fold loop. B / D handle the k3 >= 64 cases (D when
        // k2 < 64, B when both k2 and k3 are >= 64 with all k_i not multiples of 64); C is
        // the bit-by-bit catch-all; E handles word-aligned n.
        // TODO: revisit the placeholder letters / numbers once consumer code stabilises.
        internal static class PentanomialReduce
        {
            internal static IReduce Create(int n, int k1, int k2, int k3)
            {
                // ORDER-CRITICAL dispatch. The branches below MUST be checked in this order:
                // each one assumes earlier branches have already ruled out their domains.
                // Reordering will silently produce wrong results because the reducer bodies
                // have narrower contracts than their domain gates state in isolation.
                //
                //   0. ((n & 63) == 0) -> E or C. Must run first. Every word-at-a-time body
                //      below relies on a partial top limb (s_n != 0): the (t << -s) modular-
                //      shift idiom corrupts at s_n = 0 and the final mask ~(ulong.MaxValue << s_n)
                //      would zero the top result limb. The word-aligned fold E handles all
                //      (k_i & 63) != 0 with n - k3 >= 64 (the B-shaped common case); C's
                //      bit-by-bit fold handles the rest of s_n = 0 (some k_i a multiple of 64,
                //      or n - k3 < 64). Both write the full top limb and skip the partial mask.
                //   1. (n - k3 < 64) -> C (bit-by-bit). Every word-at-a-time body below (A
                //      family, B, D) requires n - k3 >= 64; otherwise a "+x^ki" tap can spill
                //      back above position n.
                //   2. (k3 < 64) -> A family (switch on n / 32). The A* bodies fuse all
                //      three "+x^ki" taps into tt[pos] / tt[pos + 1] because k1, k2, k3 are
                //      all < 64.
                //   3. (k2 < 64 && (k3 & 63) != 0) -> D. Picks off the k2 < 64 sub-domain of
                //      B where "+x^k1" and "+x^k2" can still fuse but "+x^k3" needs the
                //      modular-shift splice. (k3 & 63) != 0 is required for that splice.
                //   4. ((k1 & 63) != 0 && (k2 & 63) != 0 && (k3 & 63) != 0) -> B. The three
                //      splices all corrupt at any s_ki = 0, so multiples of 64 fall through.
                //   5. fall-through -> C (bit-by-bit). Catches the residual cases where
                //      some k_i is a multiple of 64.
                //
                // Within the (n / 32) switch the arms are mutually exclusive and order
                // doesn't matter; see the per-class header comments and the
                // PentanomialReduce-level naming doc above for the per-arm domains.

                if ((n & 63) == 0)
                {
                    if (n - k3 >= 64 && (k1 & 63) != 0 && (k2 & 63) != 0 && (k3 & 63) != 0)
                        return new E(n, k1, k2, k3);
                    return new C(n, k1, k2, k3);
                }
                if (n - k3 < 64)
                    return new C(n, k1, k2, k3);
                if (k3 < 64)
                {
                    switch (n / 32)
                    {
                    case 2:  return new A3(n, k1, k2, k3);   // n in [67,  95], tt[3] slack
                    case 3:  return new A4(n, k1, k2, k3);   // n in [97, 127]
                    case 4:  return new A5(n, k1, k2, k3);   // n in [129, 159], tt[5] slack
                    case 5:  return new A6(n, k1, k2, k3);   // n in [161, 191]
                    case 6:  return new A7(n, k1, k2, k3);   // n in [193, 223], tt[7] slack
                    case 7:  return new A8(n, k1, k2, k3);   // n in [225, 255]
                    default: return new A(n, k1, k2, k3);    // n >= 257 (w_n >= 4)
                    }
                }
                if (k2 < 64 && (k3 & 63) != 0)
                    return new D(n, k1, k2, k3);
                if ((k1 & 63) != 0 && (k2 & 63) != 0 && (k3 & 63) != 0)
                    return new B(n, k1, k2, k3);
                return new C(n, k1, k2, k3);
            }

            // Sub-case A: word-at-a-time top-down fold, all k_i < 64 and n - k3 >= 64,
            // w_n >= 4 (w_n == 1 carved into A3 [slack] / A4 [non-slack], w_n == 2 into
            // A5 / A6, w_n == 3 into A7 / A8). Fuses the "+1" and three "+x^ki" low-part
            // writes into a single XOR per limb. Used by sect283 (w_n = 4) and sect571
            // (w_n = 8).
            // The inter-iteration register-carry trick used in TrinomialReduce.A does not
            // transfer here: the cross-iteration dependency chain through the carry register
            // would be 3 XORs (one per k_i) instead of 1, and that serialization cost
            // outweighs the memory-traffic saving for the pentanomial body.
            internal sealed class A : IReduce
            {
                private readonly int m_n, m_k1, m_k2, m_k3;

                internal A(int n, int k1, int k2, int k3)
                {
                    Debug.Assert((n & 63) != 0 && k3 < 64 && n - k3 >= 64 && n / 32 >= 8);
                    m_n = n;
                    m_k1 = k1;
                    m_k2 = k2;
                    m_k3 = k3;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n >= 4);

                    // Inter-iteration upper-half load cache: this iter's tLow
                    // (= tt[pos + w_n]) is exactly the next iter's tHigh
                    // (= tt[(pos - 1) + w_n + 1] = tt[pos + w_n]), so we carry it
                    // forward in tHigh instead of re-loading.
                    int pos = w_n;
                    ulong tHigh = tt[ttOff + pos + w_n + 1];
                    ulong tLow  = tt[ttOff + pos + w_n    ];
                    ulong t = (tLow >> s_n) | (tHigh << -s_n);
                    tt[ttOff + pos    ] ^= t ^ t <<  k1 ^ t <<  k2 ^ t <<  k3;
                    tt[ttOff + pos + 1] ^=     t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    while (--pos >= 0)
                    {
                        tHigh = tLow;
                        tLow = tt[ttOff + pos + w_n];
                        t = (tLow >> s_n) | (tHigh << -s_n);
                        tt[ttOff + pos    ] ^= t ^ t <<  k1 ^ t <<  k2 ^ t <<  k3;
                        tt[ttOff + pos + 1] ^=     t >> -k1 ^ t >> -k2 ^ t >> -k3;
                    }

                    Array.Copy(tt, ttOff, z, zOff, w_n);
                    z[zOff + w_n] = tt[ttOff + w_n] & ~(ulong.MaxValue << s_n);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n >= 4);

                    // Inter-iteration upper-half load cache: this iter's tLow
                    // (= tt[pos + w_n]) is exactly the next iter's tHigh
                    // (= tt[(pos - 1) + w_n + 1] = tt[pos + w_n]), so we carry it
                    // forward in tHigh instead of re-loading.
                    int pos = w_n;
                    ulong tHigh = tt[pos + w_n + 1];
                    ulong tLow  = tt[pos + w_n    ];
                    ulong t = (tLow >> s_n) | (tHigh << -s_n);
                    tt[pos    ] ^= t ^ t <<  k1 ^ t <<  k2 ^ t <<  k3;
                    tt[pos + 1] ^=     t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    while (--pos >= 0)
                    {
                        tHigh = tLow;
                        tLow = tt[pos + w_n];
                        t = (tLow >> s_n) | (tHigh << -s_n);
                        tt[pos    ] ^= t ^ t <<  k1 ^ t <<  k2 ^ t <<  k3;
                        tt[pos + 1] ^=     t >> -k1 ^ t >> -k2 ^ t >> -k3;
                    }

                    tt.Slice(0, w_n).CopyTo(z);
                    z[w_n] = tt[w_n] & ~(ulong.MaxValue << s_n);
                }
#endif
            }

            // Sub-case A3: size-2 trinomial-style fold, slack subrange (n in [67, 95], all
            // k_i < 64, n - k3 >= 64; 2n - 1 <= 189 so tt[3] is zero by the IReduce
            // contract). Fully unrolled, tt[0..2] held in locals (3 limbs); the result is
            // written directly to z[0..1] (no tt staging buffer copy). No SECT pentanomial
            // hits this branch.
            internal sealed class A3 : IReduce
            {
                private readonly int m_n, m_k1, m_k2, m_k3;

                internal A3(int n, int k1, int k2, int k3)
                {
                    Debug.Assert((n & 63) != 0 && k3 < 64 && n - k3 >= 64 && n / 32 == 2);
                    m_n = n;
                    m_k1 = k1;
                    m_k2 = k2;
                    m_k3 = k3;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 1);

                    // Load tt[0..2] into locals; tt[3] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2];

                    // Unrolled top-down word fold (pos = 1, 0). At pos = 1 the read
                    // simplifies because tt[3] = 0.
                    ulong t = t2 >> s_n;                       // pos = 1 (tt[3] is zero)
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t1 >> s_n) | (t2 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    z[zOff] = t0;
                    z[zOff + 1] = t1 & ~(ulong.MaxValue << s_n);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 1);

                    // Load tt[0..2] into locals; tt[3] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2];

                    // Unrolled top-down word fold (pos = 1, 0). At pos = 1 the read
                    // simplifies because tt[3] = 0.
                    ulong t = t2 >> s_n;                       // pos = 1 (tt[3] is zero)
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t1 >> s_n) | (t2 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    z[0] = t0;
                    z[1] = t1 & ~(ulong.MaxValue << s_n);
                }
#endif
            }

            // Sub-case A4: size-2 pentanomial fold, non-slack subrange (n in [97, 127];
            // the slack subrange n in [67, 95] is carved out into A3). Fully unrolled,
            // tt[0..3] held in locals (4 limbs); the result is written directly to z[0..1]
            // (no tt staging buffer copy). No SECT pentanomial hits this branch.
            internal sealed class A4 : IReduce
            {
                private readonly int m_n, m_k1, m_k2, m_k3;

                internal A4(int n, int k1, int k2, int k3)
                {
                    Debug.Assert((n & 63) != 0 && k3 < 64 && n - k3 >= 64 && n / 32 == 3);
                    m_n = n;
                    m_k1 = k1;
                    m_k2 = k2;
                    m_k3 = k3;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 1);

                    // Load tt[0..3] into locals.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2], t3 = tt[ttOff + 3];

                    // Unrolled top-down word fold (pos = 1, 0).
                    ulong t = (t2 >> s_n) | (t3 << -s_n);      // pos = 1
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t1 >> s_n) | (t2 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    z[zOff] = t0;
                    z[zOff + 1] = t1 & ~(ulong.MaxValue << s_n);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 1);

                    // Load tt[0..3] into locals.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2], t3 = tt[3];

                    // Unrolled top-down word fold (pos = 1, 0).
                    ulong t = (t2 >> s_n) | (t3 << -s_n);      // pos = 1
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t1 >> s_n) | (t2 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    z[0] = t0;
                    z[1] = t1 & ~(ulong.MaxValue << s_n);
                }
#endif
            }

            // Sub-case A5: size-3 pentanomial fold, slack subrange (n in [129, 159]; 2n - 1
            // <= 317 so tt[5] is zero by the IReduce contract). Fully unrolled, tt[0..4]
            // held in locals (5 limbs); the result is written directly to z[0..2] (no tt
            // staging buffer copy). Used by sect131 (n=131, k1=2, k2=3, k3=8).
            internal sealed class A5 : IReduce
            {
                private readonly int m_n, m_k1, m_k2, m_k3;

                internal A5(int n, int k1, int k2, int k3)
                {
                    Debug.Assert((n & 63) != 0 && k3 < 64 && n - k3 >= 64 && n / 32 == 4);
                    m_n = n;
                    m_k1 = k1;
                    m_k2 = k2;
                    m_k3 = k3;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 2);

                    // Load tt[0..4] into locals; tt[5] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2];
                    ulong t3 = tt[ttOff + 3], t4 = tt[ttOff + 4];

                    // Unrolled top-down word fold (pos = 2, 1, 0). At pos = 2 the read
                    // simplifies because tt[5] = 0.
                    ulong t = t4 >> s_n;                       // pos = 2 (tt[5] is zero)
                    t2 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t3 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t3 >> s_n) | (t4 << -s_n);            // pos = 1
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t2 >> s_n) | (t3 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 2);

                    // Load tt[0..4] into locals; tt[5] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2];
                    ulong t3 = tt[3], t4 = tt[4];

                    // Unrolled top-down word fold (pos = 2, 1, 0). At pos = 2 the read
                    // simplifies because tt[5] = 0.
                    ulong t = t4 >> s_n;                       // pos = 2 (tt[5] is zero)
                    t2 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t3 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t3 >> s_n) | (t4 << -s_n);            // pos = 1
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t2 >> s_n) | (t3 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                }
#endif
            }

            // Sub-case A6: size-3 pentanomial fold, non-slack subrange (n in [161, 191];
            // the slack subrange n in [129, 159] is carved out into A5). Fully unrolled,
            // tt[0..5] held in locals (6 limbs); the result is written directly to z[0..2]
            // (no tt staging buffer copy). Used by sect163 (n=163, k1=3, k2=6, k3=7).
            internal sealed class A6 : IReduce
            {
                private readonly int m_n, m_k1, m_k2, m_k3;

                internal A6(int n, int k1, int k2, int k3)
                {
                    Debug.Assert((n & 63) != 0 && k3 < 64 && n - k3 >= 64 && n / 32 == 5);
                    m_n = n;
                    m_k1 = k1;
                    m_k2 = k2;
                    m_k3 = k3;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 2);

                    // Load tt[0..5] into locals.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2];
                    ulong t3 = tt[ttOff + 3], t4 = tt[ttOff + 4], t5 = tt[ttOff + 5];

                    // Unrolled top-down word fold (pos = 2, 1, 0).
                    ulong t = (t4 >> s_n) | (t5 << -s_n);      // pos = 2
                    t2 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t3 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t3 >> s_n) | (t4 << -s_n);            // pos = 1
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t2 >> s_n) | (t3 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 2);

                    // Load tt[0..5] into locals.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2];
                    ulong t3 = tt[3], t4 = tt[4], t5 = tt[5];

                    // Unrolled top-down word fold (pos = 2, 1, 0).
                    ulong t = (t4 >> s_n) | (t5 << -s_n);      // pos = 2
                    t2 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t3 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t3 >> s_n) | (t4 << -s_n);            // pos = 1
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t2 >> s_n) | (t3 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                }
#endif
            }

            // Sub-case A7: size-4 pentanomial fold, slack subrange (n in [193, 223]; 2n - 1
            // <= 445 so tt[7] is zero by the IReduce contract). Fully unrolled, tt[0..6]
            // held in locals (7 limbs); the result is written directly to z[0..3] (no tt
            // staging buffer copy). No SECT pentanomial hits this branch.
            internal sealed class A7 : IReduce
            {
                private readonly int m_n, m_k1, m_k2, m_k3;

                internal A7(int n, int k1, int k2, int k3)
                {
                    Debug.Assert((n & 63) != 0 && k3 < 64 && n - k3 >= 64 && n / 32 == 6);
                    m_n = n;
                    m_k1 = k1;
                    m_k2 = k2;
                    m_k3 = k3;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 3);

                    // Load tt[0..6] into locals; tt[7] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2], t3 = tt[ttOff + 3];
                    ulong t4 = tt[ttOff + 4], t5 = tt[ttOff + 5], t6 = tt[ttOff + 6];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0). At pos = 3 the read
                    // simplifies because tt[7] = 0.
                    ulong t = t6 >> s_n;                       // pos = 3 (tt[7] is zero)
                    t3 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t4 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t5 >> s_n) | (t6 << -s_n);            // pos = 2
                    t2 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t3 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t4 >> s_n) | (t5 << -s_n);            // pos = 1
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t3 >> s_n) | (t4 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    // Mask off bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                    z[zOff + 3] = t3;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 3);

                    // Load tt[0..6] into locals; tt[7] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2], t3 = tt[3];
                    ulong t4 = tt[4], t5 = tt[5], t6 = tt[6];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0). At pos = 3 the read
                    // simplifies because tt[7] = 0.
                    ulong t = t6 >> s_n;                       // pos = 3 (tt[7] is zero)
                    t3 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t4 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t5 >> s_n) | (t6 << -s_n);            // pos = 2
                    t2 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t3 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t4 >> s_n) | (t5 << -s_n);            // pos = 1
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t3 >> s_n) | (t4 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    // Mask off bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                    z[3] = t3;
                }
#endif
            }

            // Sub-case A8: size-4 pentanomial fold, non-slack subrange (n in [225, 255];
            // the slack subrange n in [193, 223] is carved out into A7). Fully unrolled,
            // tt[0..7] held in locals (8 limbs); the result is written directly to z[0..3]
            // (no tt staging buffer copy). No SECT pentanomial hits this branch.
            internal sealed class A8 : IReduce
            {
                private readonly int m_n, m_k1, m_k2, m_k3;

                internal A8(int n, int k1, int k2, int k3)
                {
                    Debug.Assert((n & 63) != 0 && k3 < 64 && n - k3 >= 64 && n / 32 == 7);
                    m_n = n;
                    m_k1 = k1;
                    m_k2 = k2;
                    m_k3 = k3;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 3);

                    // Load tt[0..7] into locals.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2], t3 = tt[ttOff + 3];
                    ulong t4 = tt[ttOff + 4], t5 = tt[ttOff + 5], t6 = tt[ttOff + 6], t7 = tt[ttOff + 7];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0).
                    ulong t = (t6 >> s_n) | (t7 << -s_n);      // pos = 3
                    t3 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t4 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t5 >> s_n) | (t6 << -s_n);            // pos = 2
                    t2 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t3 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t4 >> s_n) | (t5 << -s_n);            // pos = 1
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t3 >> s_n) | (t4 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    // Mask off bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                    z[zOff + 3] = t3;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 3);

                    // Load tt[0..7] into locals.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2], t3 = tt[3];
                    ulong t4 = tt[4], t5 = tt[5], t6 = tt[6], t7 = tt[7];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0).
                    ulong t = (t6 >> s_n) | (t7 << -s_n);      // pos = 3
                    t3 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t4 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t5 >> s_n) | (t6 << -s_n);            // pos = 2
                    t2 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t3 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t4 >> s_n) | (t5 << -s_n);            // pos = 1
                    t1 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t2 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    t = (t3 >> s_n) | (t4 << -s_n);            // pos = 0
                    t0 ^= t ^ t << k1 ^ t << k2 ^ t << k3;
                    t1 ^= t >> -k1 ^ t >> -k2 ^ t >> -k3;

                    // Mask off bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                    z[3] = t3;
                }
#endif
            }

            // Sub-case B: word-at-a-time top-down fold, k2 > 64 (so also k3 > 64) with
            // (k_i & 63) != 0 for all k_i, and n - k3 >= 64. (k2 == 64 fails the (k2 & 63) != 0
            // gate and falls through to C.) Each "+x^ki" tap uses the modular-shift splice via
            // Pos(k_i, ...); if k1 < 64 the k1 splice still resolves to writes in tt[pos] and
            // tt[pos + 1] (equivalent to A's fused form, just less compact). The k2 < 64
            // sub-case is carved out into D, which fuses the "+x^k1" and "+x^k2" taps with
            // the "+1" tap. No SECT pentanomial hits this branch.
            internal sealed class B : IReduce
            {
                private readonly int m_n, m_k1, m_k2, m_k3;

                internal B(int n, int k1, int k2, int k3)
                {
                    Debug.Assert((n & 63) != 0 && k2 >= 64 && n - k3 >= 64 &&
                        (k1 & 63) != 0 && (k2 & 63) != 0 && (k3 & 63) != 0);
                    m_n = n;
                    m_k1 = k1;
                    m_k2 = k2;
                    m_k3 = k3;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k1, out int w_k1, out int s_k1);
                    Pos(k2, out int w_k2, out int s_k2);
                    Pos(k3, out int w_k3, out int s_k3);

                    int pos = w_n;
                    do
                    {
                        ulong t = tt[ttOff + pos + w_n    ] >>  s_n
                                | tt[ttOff + pos + w_n + 1] << -s_n;

                        tt[ttOff + pos] ^= t;

                        tt[ttOff + pos + w_k1    ] ^= t <<  s_k1;
                        tt[ttOff + pos + w_k1 + 1] ^= t >> -s_k1;

                        tt[ttOff + pos + w_k2    ] ^= t <<  s_k2;
                        tt[ttOff + pos + w_k2 + 1] ^= t >> -s_k2;

                        tt[ttOff + pos + w_k3    ] ^= t <<  s_k3;
                        tt[ttOff + pos + w_k3 + 1] ^= t >> -s_k3;
                    }
                    while (--pos >= 0);

                    Array.Copy(tt, ttOff, z, zOff, w_n);
                    z[zOff + w_n] = tt[ttOff + w_n] & ~(ulong.MaxValue << s_n);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k1, out int w_k1, out int s_k1);
                    Pos(k2, out int w_k2, out int s_k2);
                    Pos(k3, out int w_k3, out int s_k3);

                    int pos = w_n;
                    do
                    {
                        ulong t = tt[pos + w_n    ] >>  s_n
                                | tt[pos + w_n + 1] << -s_n;

                        tt[pos] ^= t;

                        tt[pos + w_k1    ] ^= t <<  s_k1;
                        tt[pos + w_k1 + 1] ^= t >> -s_k1;

                        tt[pos + w_k2    ] ^= t <<  s_k2;
                        tt[pos + w_k2 + 1] ^= t >> -s_k2;

                        tt[pos + w_k3    ] ^= t <<  s_k3;
                        tt[pos + w_k3 + 1] ^= t >> -s_k3;
                    }
                    while (--pos >= 0);

                    tt.Slice(0, w_n).CopyTo(z);
                    z[w_n] = tt[w_n] & ~(ulong.MaxValue << s_n);
                }
#endif
            }

            // Sub-case D: word-at-a-time top-down fold, k2 < 64 (so k1, k2 both < 64) and
            // k3 >= 64 with (k3 & 63) != 0, and n - k3 >= 64. Fuses the "+1", "+x^k1" and
            // "+x^k2" taps into A-style writes to tt[pos] and tt[pos + 1] (k1, k2 < 64), and
            // uses a B-style modular-shift splice for the "+x^k3" tap. Saves one fused XOR
            // pair per iteration over B at the cost of carrying the k3 splice. Minimum n in
            // this domain is 129 (w_n >= 2 invariant). No SECT pentanomial hits this branch.
            internal sealed class D : IReduce
            {
                private readonly int m_n, m_k1, m_k2, m_k3;

                internal D(int n, int k1, int k2, int k3)
                {
                    Debug.Assert((n & 63) != 0 && k2 < 64 && k3 >= 64 && (k3 & 63) != 0 && n - k3 >= 64);
                    m_n = n;
                    m_k1 = k1;
                    m_k2 = k2;
                    m_k3 = k3;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k3, out int w_k3, out int s_k3);
                    Debug.Assert(w_n >= 2);

                    int pos = w_n;
                    do
                    {
                        ulong t = tt[ttOff + pos + w_n    ] >>  s_n
                                | tt[ttOff + pos + w_n + 1] << -s_n;

                        tt[ttOff + pos    ] ^= t ^ t <<  k1 ^ t <<  k2;
                        tt[ttOff + pos + 1] ^=     t >> -k1 ^ t >> -k2;

                        tt[ttOff + pos + w_k3    ] ^= t <<  s_k3;
                        tt[ttOff + pos + w_k3 + 1] ^= t >> -s_k3;
                    }
                    while (--pos >= 0);

                    Array.Copy(tt, ttOff, z, zOff, w_n);
                    z[zOff + w_n] = tt[ttOff + w_n] & ~(ulong.MaxValue << s_n);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k3, out int w_k3, out int s_k3);
                    Debug.Assert(w_n >= 2);

                    int pos = w_n;
                    do
                    {
                        ulong t = tt[pos + w_n    ] >>  s_n
                                | tt[pos + w_n + 1] << -s_n;

                        tt[pos    ] ^= t ^ t <<  k1 ^ t <<  k2;
                        tt[pos + 1] ^=     t >> -k1 ^ t >> -k2;

                        tt[pos + w_k3    ] ^= t <<  s_k3;
                        tt[pos + w_k3 + 1] ^= t >> -s_k3;
                    }
                    while (--pos >= 0);

                    tt.Slice(0, w_n).CopyTo(z);
                    z[w_n] = tt[w_n] & ~(ulong.MaxValue << s_n);
                }
#endif
            }

            // Sub-case C: bit-by-bit top-down fold. Catches everything not handled by A, B, D
            // or E: n - k3 < 64, k3 a multiple of 64, or k2 >= 64 with some k_i a multiple of 64,
            // plus the residual (n & 63) == 0 cases not taken by E (some k_i a multiple of 64, or
            // n - k3 < 64) — where the word-at-a-time bodies' (t << -s) idiom and final mask break
            // at s_n = 0. The fold is parity-agnostic and the final write skips the partial-limb
            // mask when s_top == 0. No standardised SECT pentanomial hits this branch;
            // correctness-defensive for arbitrary (n, k1, k2, k3).
            internal sealed class C : IReduce
            {
                private readonly int m_n, m_k1, m_k2, m_k3;

                internal C(int n, int k1, int k2, int k3)
                {
                    Debug.Assert(n - k3 < 64 || (k1 & 63) == 0 || (k2 & 63) == 0 || (k3 & 63) == 0);
                    m_n = n;
                    m_k1 = k1;
                    m_k2 = k2;
                    m_k3 = k3;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt, ttOff);

                    int pos_0 = n - 1;
                    while (--pos_0 >= 0)
                    {
                        Pos(pos_0 + n, out int w_n, out int s_n);
                        ulong bit_n = (tt[ttOff + w_n] >> s_n) & 1UL;

                        Pos(pos_0, out int w_0, out int s_0);
                        tt[ttOff + w_0] ^= bit_n << s_0;

                        Pos(pos_0 + k1, out int w_k1, out int s_k1);
                        tt[ttOff + w_k1] ^= bit_n << s_k1;

                        Pos(pos_0 + k2, out int w_k2, out int s_k2);
                        tt[ttOff + w_k2] ^= bit_n << s_k2;

                        Pos(pos_0 + k3, out int w_k3, out int s_k3);
                        tt[ttOff + w_k3] ^= bit_n << s_k3;
                    }

                    Pos(n, out int w_top, out int s_top);
                    Array.Copy(tt, ttOff, z, zOff, w_top);
                    // s_top == 0 (n a multiple of 64): the copy above already wrote the full top
                    // limb (w_top == size); no partial-limb mask, and z has no limb w_top to write.
                    if (s_top != 0)
                        z[zOff + w_top] = tt[ttOff + w_top] & ~(ulong.MaxValue << s_top);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt);

                    int pos_0 = n - 1;
                    while (--pos_0 >= 0)
                    {
                        Pos(pos_0 + n, out int w_n, out int s_n);
                        ulong bit_n = (tt[w_n] >> s_n) & 1UL;

                        Pos(pos_0, out int w_0, out int s_0);
                        tt[w_0] ^= bit_n << s_0;

                        Pos(pos_0 + k1, out int w_k1, out int s_k1);
                        tt[w_k1] ^= bit_n << s_k1;

                        Pos(pos_0 + k2, out int w_k2, out int s_k2);
                        tt[w_k2] ^= bit_n << s_k2;

                        Pos(pos_0 + k3, out int w_k3, out int s_k3);
                        tt[w_k3] ^= bit_n << s_k3;
                    }

                    Pos(n, out int w_top, out int s_top);
                    tt.Slice(0, w_top).CopyTo(z);
                    // s_top == 0 (n a multiple of 64): the copy above already wrote the full top
                    // limb (w_top == size); no partial-limb mask, and z has no limb w_top to write.
                    if (s_top != 0)
                        z[w_top] = tt[w_top] & ~(ulong.MaxValue << s_top);
                }
#endif
            }

            // Sub-case E: word-aligned n ((n & 63) == 0), with all (k_i & 63) != 0 and
            // n - k3 >= 64. The word-aligned analogue of B: with s_n == 0 the "+1" read needs no
            // cross-word splice, so t is just the high word tt[pos + W] read directly, and the
            // result is W = n / 64 full limbs (no partial top limb to mask). The dispatch
            // preconditions force w_k3 <= W - 2 (and w_k1 <= w_k2 <= w_k3), so every "+x^ki" splice
            // writes only to limbs strictly below the current high word (pos + W) -- the single
            // top-down sweep folds every high limb without re-reading. No SECT pentanomial hits
            // this branch; it is correctness-defensive for arbitrary (n, k1, k2, k3) supplied via
            // the future F2mFieldElement replacement.
            internal sealed class E : IReduce
            {
                private readonly int m_n, m_k1, m_k2, m_k3;

                internal E(int n, int k1, int k2, int k3)
                {
                    Debug.Assert((n & 63) == 0 && (k1 & 63) != 0 && (k2 & 63) != 0 && (k3 & 63) != 0 && n - k3 >= 64);
                    m_n = n;
                    m_k1 = k1;
                    m_k2 = k2;
                    m_k3 = k3;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    int W = n >> 6;
                    Pos(k1, out int w_k1, out int s_k1);
                    Pos(k2, out int w_k2, out int s_k2);
                    Pos(k3, out int w_k3, out int s_k3);
                    Debug.Assert(s_k1 != 0 && s_k2 != 0 && s_k3 != 0 && w_k3 <= W - 2);

                    int pos = W - 1;
                    do
                    {
                        ulong t = tt[ttOff + pos + W];

                        tt[ttOff + pos] ^= t;

                        tt[ttOff + pos + w_k1    ] ^= t <<  s_k1;
                        tt[ttOff + pos + w_k1 + 1] ^= t >> -s_k1;

                        tt[ttOff + pos + w_k2    ] ^= t <<  s_k2;
                        tt[ttOff + pos + w_k2 + 1] ^= t >> -s_k2;

                        tt[ttOff + pos + w_k3    ] ^= t <<  s_k3;
                        tt[ttOff + pos + w_k3 + 1] ^= t >> -s_k3;
                    }
                    while (--pos >= 0);

                    Array.Copy(tt, ttOff, z, zOff, W);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k1 = m_k1, k2 = m_k2, k3 = m_k3;
                    DebugAssertReducePreconditions(n, tt);
                    int W = n >> 6;
                    Pos(k1, out int w_k1, out int s_k1);
                    Pos(k2, out int w_k2, out int s_k2);
                    Pos(k3, out int w_k3, out int s_k3);
                    Debug.Assert(s_k1 != 0 && s_k2 != 0 && s_k3 != 0 && w_k3 <= W - 2);

                    int pos = W - 1;
                    do
                    {
                        ulong t = tt[pos + W];

                        tt[pos] ^= t;

                        tt[pos + w_k1    ] ^= t <<  s_k1;
                        tt[pos + w_k1 + 1] ^= t >> -s_k1;

                        tt[pos + w_k2    ] ^= t <<  s_k2;
                        tt[pos + w_k2 + 1] ^= t >> -s_k2;

                        tt[pos + w_k3    ] ^= t <<  s_k3;
                        tt[pos + w_k3 + 1] ^= t >> -s_k3;
                    }
                    while (--pos >= 0);

                    tt.Slice(0, W).CopyTo(z);
                }
#endif
            }
        }
    }
}
