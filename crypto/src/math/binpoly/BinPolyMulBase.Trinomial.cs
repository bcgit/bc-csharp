using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.BinPoly
{
    internal abstract partial class BinPolyMulBase
    {
        // Trinomial reduction by x^n + x^k + 1. The factory selects one of several specialized
        // implementations based on (n, k); each has a streamlined Reduce body for its case. Each
        // bit at position p >= n folds via the "+1" tap to position (p - n) and via the "+x^k"
        // tap to position (p - n + k). n need not be odd; the word-at-a-time variants require a
        // partial top limb ((n & 63) != 0). The factory routes word-aligned n ((n & 63) == 0) to
        // E (the word-aligned analogue of C, when (k & 63) != 0 and n - k >= 64) or otherwise to
        // the bitwise reducer D.
        //
        // Sub-case naming: A<N> / C<N> denotes a fully-unrolled size-K reducer that loads N
        // limbs of tt. Each polynomial size K = w_n + 1 has a paired (slack, non-slack)
        // flavour: slack uses (2K - 1) limbs (the topmost limb tt[2K - 1] is zero by the
        // IReduce contract for low-enough n), and non-slack uses 2K. The A family (k < 64)
        // covers sizes 2, 3, 4 with A3 / A4, A5 / A6, A7 / A8; the C family ((k & 63) != 0,
        // k >= 64) mirrors sizes 3 and 4 with C5 / C6 and C7 / C8. The plain A / C classes
        // handle w_n >= 4 (n >= 257) via the inter-iteration carry loop and the bit-by-bit
        // splice respectively. B / D handle the k-a-multiple-of-64 and small-(n - k) edge
        // cases; E handles word-aligned n.
        // TODO: revisit the placeholder letters / numbers once consumer code stabilises.
        internal static class TrinomialReduce
        {
            internal static IReduce Create(int n, int k)
            {
                // ORDER-CRITICAL dispatch. The top-level branches below MUST be checked in
                // this order: each one assumes earlier branches have already ruled out their
                // domains. Reordering will silently produce wrong results because the reducer
                // bodies have narrower contracts than their domain gates state in isolation.
                //
                //   0. ((n & 63) == 0) -> E or D. Must run first. Every word-at-a-time body
                //      below relies on a partial top limb (s_n != 0): the (t << -s) modular-
                //      shift idiom corrupts at s_n = 0 and the final mask ~(ulong.MaxValue << s_n)
                //      would zero the top result limb. The word-aligned fold E handles
                //      (k & 63) != 0 with n - k >= 64 (the common case); D's bit-by-bit fold
                //      handles the rest of s_n = 0 (k a multiple of 64, or n - k < 64). Both
                //      write the full top limb and skip the partial-limb mask.
                //   1. (n - k < 64) -> D. Every word-at-a-time body below (A family, B, C
                //      family) requires n - k >= 64; otherwise the "+x^k" tap can spill back
                //      above position n and would need iterating, which only D's bit-by-bit
                //      fold handles.
                //   2. (k < 64) -> A family. Must precede the B / C tests because A's
                //      bodies assume k < 64 (so w_k = 0 and the "+x^k" tap fuses into
                //      tt[pos] / tt[pos + 1] without a Pos(k) splice).
                //   3. ((k & 63) == 0) -> B. Must precede the C family: C's modular-
                //      shift splice (t << -s_k / t >> -s_k) corrupts at s_k = 0, and B's
                //      word-aligned form is also faster.
                //   4. fall-through -> C family (k >= 64, (k & 63) != 0, n - k >= 64).
                //
                // Within each (n / 32) switch the arms are mutually exclusive and order
                // doesn't matter; see the per-class header comments and the
                // TrinomialReduce-level naming doc above for the per-arm domains.

                if ((n & 63) == 0)
                {
                    if (n - k >= 64 && (k & 63) != 0)
                        return new E(n, k);
                    return new D(n, k);
                }
                if (n - k < 64)
                    return new D(n, k);
                if (k < 64)
                {
                    switch (n / 32)
                    {
                    case 2:  return new A3(n, k);   // n in [65,  95], tt[3] slack
                    case 3:  return new A4(n, k);   // n in [97, 127]
                    case 4:  return new A5(n, k);   // n in [129, 159], tt[5] slack
                    case 5:  return new A6(n, k);   // n in [161, 191]
                    case 6:  return new A7(n, k);   // n in [193, 223], tt[7] slack
                    case 7:  return new A8(n, k);   // n in [225, 255]
                    default: return new A(n, k);    // n >= 257 (w_n >= 4)
                    }
                }
                if ((k & 63) == 0)
                    return new B(n, k);
                switch (n / 32)
                {
                case 4:  return new C5(n, k);   // n in [129, 159], tt[5] slack
                case 5:  return new C6(n, k);   // n in [161, 191]
                case 6:  return new C7(n, k);   // n in [193, 223], tt[7] slack
                case 7:  return new C8(n, k);   // n in [225, 255]
                default: return new C(n, k);    // n >= 257 (w_n >= 4)
                }
            }

            // Sub-case A: word-at-a-time top-down fold, k < 64 and n - k >= 64, w_n >= 4
            // (w_n == 1 carved into A3 [slack] / A4 [non-slack], w_n == 2 into A5 / A6, and
            // w_n == 3 into A7 / A8). Reachable n: 257 and above.
            // Fuses the "+1" and "+x^k" low-part writes into a single XOR per limb. Uses an
            // inter-iteration register-carry: the carry register r holds the in-flight value
            // of tt[pos + 1] across the iteration boundary, absorbing both writes that touch
            // each interior limb (the "+1" / "+x^k low" XOR from iteration pos + 1, and the
            // "+x^k high" XOR from iteration pos). The potential alias (the next iteration's
            // read tt[(pos - 1) + w_n] coinciding with the held-in-r tt[pos], which would
            // require w_n == 1) cannot occur because that case is in A4. No SECT trinomial
            // hits this branch.
            internal sealed class A : IReduce
            {
                private readonly int m_n, m_k;

                internal A(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k < 64 && n - k >= 64 && n / 32 >= 8);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n >= 4);

                    // Inter-iteration register-carry. r holds the in-flight value of
                    // tt[pos + 1] coming into each iteration. The upper-half load is also
                    // carried across iterations via a 2-limb rolling window (tHigh, tLow):
                    // this iter's tLow (= tt[pos + w_n]) is exactly the next iter's tHigh
                    // (= tt[(pos - 1) + w_n + 1]), so each tt limb is loaded once.
                    int pos = w_n;
                    ulong tHigh = tt[ttOff + pos + w_n + 1];
                    ulong tLow  = tt[ttOff + pos + w_n    ];
                    ulong tFirst = (tLow >> s_n) | (tHigh << -s_n);
                    ulong r = tt[ttOff + pos] ^ tFirst ^ tFirst << k;
                    tt[ttOff + pos + 1] ^= tFirst >> -k;   // finalize tt[w_n + 1] via mem RMW

                    while (--pos >= 0)
                    {
                        tHigh = tLow;
                        tLow = tt[ttOff + pos + w_n];
                        ulong t = (tLow >> s_n) | (tHigh << -s_n);
                        r ^= t >> -k;
                        tt[ttOff + pos + 1] = r;
                        r = tt[ttOff + pos] ^ t ^ t << k;
                    }

                    z[zOff] = r;
                    Array.Copy(tt, ttOff + 1, z, zOff + 1, w_n - 1);
                    z[zOff + w_n] = tt[ttOff + w_n] & ~(ulong.MaxValue << s_n);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n >= 4);

                    // Inter-iteration register-carry. r holds the in-flight value of
                    // tt[pos + 1] coming into each iteration. The upper-half load is also
                    // carried across iterations via a 2-limb rolling window (tHigh, tLow):
                    // this iter's tLow (= tt[pos + w_n]) is exactly the next iter's tHigh
                    // (= tt[(pos - 1) + w_n + 1]), so each tt limb is loaded once.
                    int pos = w_n;
                    ulong tHigh = tt[pos + w_n + 1];
                    ulong tLow  = tt[pos + w_n    ];
                    ulong tFirst = (tLow >> s_n) | (tHigh << -s_n);
                    ulong r = tt[pos] ^ tFirst ^ tFirst << k;
                    tt[pos + 1] ^= tFirst >> -k;   // finalize tt[w_n + 1] via mem RMW

                    while (--pos >= 0)
                    {
                        tHigh = tLow;
                        tLow = tt[pos + w_n];
                        ulong t = (tLow >> s_n) | (tHigh << -s_n);
                        r ^= t >> -k;
                        tt[pos + 1] = r;
                        r = tt[pos] ^ t ^ t << k;
                    }

                    z[0] = r;
                    tt.Slice(1, w_n - 1).CopyTo(z.Slice(1));
                    z[w_n] = tt[w_n] & ~(ulong.MaxValue << s_n);
                }
#endif
            }

            // Sub-case A3: size-2 trinomials, slack subrange (n in [65, 95], so 2n - 1 <= 189
            // and tt[3] is zero by the IReduce contract). Fully unrolled, tt[0..2] held in
            // locals (3 limbs); the result is written directly to z[0..1] (no tt staging
            // buffer copy). No SECT trinomial hits this branch.
            internal sealed class A3 : IReduce
            {
                private readonly int m_n, m_k;

                internal A3(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k < 64 && n - k >= 64 && n / 32 == 2);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 1);

                    // Load tt[0..2] into locals; tt[3] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2];

                    // Unrolled top-down word fold (pos = 1, 0). At pos = 1 the read simplifies
                    // because tt[3] = 0.
                    ulong t = t2 >> s_n;                    // pos = 1 (tt[3] is zero)
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t1 >> s_n) | (t2 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    z[zOff] = t0;
                    z[zOff + 1] = t1 & ~(ulong.MaxValue << s_n);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 1);

                    // Load tt[0..2] into locals; tt[3] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2];

                    // Unrolled top-down word fold (pos = 1, 0). At pos = 1 the read simplifies
                    // because tt[3] = 0.
                    ulong t = t2 >> s_n;                    // pos = 1 (tt[3] is zero)
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t1 >> s_n) | (t2 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    z[0] = t0;
                    z[1] = t1 & ~(ulong.MaxValue << s_n);
                }
#endif
            }

            // Sub-case A4: size-2 trinomials, non-slack subrange (n in [97, 127]; the slack
            // subrange n in [65, 95] is carved out into A3). Fully unrolled, tt[0..3] held in
            // locals (4 limbs); the result is written directly to z[0..1] (no tt staging
            // buffer copy). Used by sect113 (n=113, k=9).
            internal sealed class A4 : IReduce
            {
                private readonly int m_n, m_k;

                internal A4(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k < 64 && n - k >= 64 && n / 32 == 3);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 1);

                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2], t3 = tt[ttOff + 3];

                    ulong t = (t2 >> s_n) | (t3 << -s_n);   // pos = 1
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t1 >> s_n) | (t2 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    z[zOff] = t0;
                    z[zOff + 1] = t1 & ~(ulong.MaxValue << s_n);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 1);

                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2], t3 = tt[3];

                    ulong t = (t2 >> s_n) | (t3 << -s_n);   // pos = 1
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t1 >> s_n) | (t2 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    z[0] = t0;
                    z[1] = t1 & ~(ulong.MaxValue << s_n);
                }
#endif
            }

            // Sub-case A5: size-3 trinomials, slack subrange (n in [129, 159], so 2n - 1 <=
            // 317 and tt[5] is zero by the IReduce contract). Fully unrolled, tt[0..4] held
            // in locals (5 limbs); the result is written directly to z[0..2] (no tt staging
            // buffer copy). No SECT trinomial hits this branch.
            internal sealed class A5 : IReduce
            {
                private readonly int m_n, m_k;

                internal A5(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k < 64 && n - k >= 64 && n / 32 == 4);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 2);

                    // Load tt[0..4] into locals; tt[5] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2];
                    ulong t3 = tt[ttOff + 3], t4 = tt[ttOff + 4];

                    // Unrolled top-down word fold (pos = 2, 1, 0). With w_k = 0 (k < 64),
                    // each iteration fuses "+1" and "+x^k low" into one XOR into tt[pos]
                    // and one XOR into tt[pos + 1]. At pos = 2 the read simplifies because
                    // tt[5] = 0.
                    ulong t = t4 >> s_n;                    // pos = 2 (tt[5] is zero)
                    t2 ^= t ^ t << k;
                    t3 ^= t >> -k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 1
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t2 >> s_n) | (t3 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    // Write the three result limbs directly to z, bypassing the tt staging copy.
                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 2);

                    // Load tt[0..4] into locals; tt[5] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2];
                    ulong t3 = tt[3], t4 = tt[4];

                    // Unrolled top-down word fold (pos = 2, 1, 0). With w_k = 0 (k < 64),
                    // each iteration fuses "+1" and "+x^k low" into one XOR into tt[pos]
                    // and one XOR into tt[pos + 1]. At pos = 2 the read simplifies because
                    // tt[5] = 0.
                    ulong t = t4 >> s_n;                    // pos = 2 (tt[5] is zero)
                    t2 ^= t ^ t << k;
                    t3 ^= t >> -k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 1
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t2 >> s_n) | (t3 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    // Write the three result limbs directly to z, bypassing the tt staging copy.
                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                }
#endif
            }

            // Sub-case A6: size-3 trinomials, non-slack subrange (n in [161, 191]; the
            // slack subrange n in [129, 159] is carved out into A5). Fully unrolled, tt[0..5]
            // held in locals (6 limbs); the result is written directly to z[0..2] (no tt
            // staging buffer copy). No SECT trinomial hits this branch.
            internal sealed class A6 : IReduce
            {
                private readonly int m_n, m_k;

                internal A6(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k < 64 && n - k >= 64 && n / 32 == 5);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 2);

                    // Load tt[0..5] into locals.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2];
                    ulong t3 = tt[ttOff + 3], t4 = tt[ttOff + 4], t5 = tt[ttOff + 5];

                    // Unrolled top-down word fold (pos = 2, 1, 0). With w_k = 0 (k < 64),
                    // each iteration fuses "+1" and "+x^k low" into one XOR into tt[pos]
                    // and one XOR into tt[pos + 1].
                    ulong t = (t4 >> s_n) | (t5 << -s_n);   // pos = 2
                    t2 ^= t ^ t << k;
                    t3 ^= t >> -k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 1
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t2 >> s_n) | (t3 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    // Write the three result limbs directly to z, bypassing the tt staging copy.
                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 2);

                    // Load tt[0..5] into locals.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2];
                    ulong t3 = tt[3], t4 = tt[4], t5 = tt[5];

                    // Unrolled top-down word fold (pos = 2, 1, 0). With w_k = 0 (k < 64),
                    // each iteration fuses "+1" and "+x^k low" into one XOR into tt[pos]
                    // and one XOR into tt[pos + 1].
                    ulong t = (t4 >> s_n) | (t5 << -s_n);   // pos = 2
                    t2 ^= t ^ t << k;
                    t3 ^= t >> -k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 1
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t2 >> s_n) | (t3 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    // Write the three result limbs directly to z, bypassing the tt staging copy.
                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                }
#endif
            }

            // Sub-case A7: size-4 trinomials, slack subrange (n in [193, 223], so 2n - 1 <=
            // 445 and tt[7] is zero by the IReduce contract). Fully unrolled, tt[0..6] held
            // in locals (7 limbs); the result is written directly to z[0..3] (no tt staging
            // buffer copy). Used by sect193 (n=193, k=15).
            internal sealed class A7 : IReduce
            {
                private readonly int m_n, m_k;

                internal A7(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k < 64 && n - k >= 64 && n / 32 == 6);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 3);

                    // Load tt[0..6] into locals; tt[7] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2], t3 = tt[ttOff + 3];
                    ulong t4 = tt[ttOff + 4], t5 = tt[ttOff + 5], t6 = tt[ttOff + 6];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0). With w_k = 0 (k < 64),
                    // A's per-iteration writes collapse the "+1" and "+x^k" low-part into one
                    // XOR into tt[pos] and one XOR into tt[pos + 1]. At pos = 3 the read
                    // simplifies because tt[7] = 0.
                    ulong t = t6 >> s_n;                    // pos = 3 (tt[7] is zero)
                    t3 ^= t ^ t << k;
                    t4 ^= t >> -k;

                    t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                    t2 ^= t ^ t << k;
                    t3 ^= t >> -k;

                    t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    // Write the four result limbs directly to z, bypassing the tt staging copy.
                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                    z[zOff + 3] = t3;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 3);

                    // Load tt[0..6] into locals; tt[7] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2], t3 = tt[3];
                    ulong t4 = tt[4], t5 = tt[5], t6 = tt[6];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0). With w_k = 0 (k < 64),
                    // A's per-iteration writes collapse the "+1" and "+x^k" low-part into one
                    // XOR into tt[pos] and one XOR into tt[pos + 1]. At pos = 3 the read
                    // simplifies because tt[7] = 0.
                    ulong t = t6 >> s_n;                    // pos = 3 (tt[7] is zero)
                    t3 ^= t ^ t << k;
                    t4 ^= t >> -k;

                    t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                    t2 ^= t ^ t << k;
                    t3 ^= t >> -k;

                    t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    // Write the four result limbs directly to z, bypassing the tt staging copy.
                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                    z[3] = t3;
                }
#endif
            }

            // Sub-case A8: size-4 trinomials, non-slack subrange (n in [225, 255]; the slack
            // subrange n in [193, 223] is carved out into A7). Fully unrolled, tt[0..7] held
            // in locals (8 limbs); the result is written directly to z[0..3] (no tt staging
            // buffer copy). No SECT trinomial hits this branch.
            internal sealed class A8 : IReduce
            {
                private readonly int m_n, m_k;

                internal A8(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k < 64 && n - k >= 64 && n / 32 == 7);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 3);

                    // Load tt[0..7] into locals.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2], t3 = tt[ttOff + 3];
                    ulong t4 = tt[ttOff + 4], t5 = tt[ttOff + 5], t6 = tt[ttOff + 6], t7 = tt[ttOff + 7];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0). With w_k = 0 (k < 64),
                    // each iteration fuses "+1" and "+x^k low" into one XOR into tt[pos] and
                    // one XOR into tt[pos + 1].
                    ulong t = (t6 >> s_n) | (t7 << -s_n);   // pos = 3
                    t3 ^= t ^ t << k;
                    t4 ^= t >> -k;

                    t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                    t2 ^= t ^ t << k;
                    t3 ^= t >> -k;

                    t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    // Write the four result limbs directly to z, bypassing the tt staging copy.
                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                    z[zOff + 3] = t3;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Debug.Assert(w_n == 3);

                    // Load tt[0..7] into locals.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2], t3 = tt[3];
                    ulong t4 = tt[4], t5 = tt[5], t6 = tt[6], t7 = tt[7];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0). With w_k = 0 (k < 64),
                    // each iteration fuses "+1" and "+x^k low" into one XOR into tt[pos] and
                    // one XOR into tt[pos + 1].
                    ulong t = (t6 >> s_n) | (t7 << -s_n);   // pos = 3
                    t3 ^= t ^ t << k;
                    t4 ^= t >> -k;

                    t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                    t2 ^= t ^ t << k;
                    t3 ^= t >> -k;

                    t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                    t1 ^= t ^ t << k;
                    t2 ^= t >> -k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                    t0 ^= t ^ t << k;
                    t1 ^= t >> -k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    // Write the four result limbs directly to z, bypassing the tt staging copy.
                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                    z[3] = t3;
                }
#endif
            }

            // Sub-case B: word-at-a-time top-down fold, k a multiple of 64 (k >= 64) and
            // n - k >= 64. The "+x^k" tap aligns with the word grid so no cross-word write is
            // needed. No SECT trinomial hits this branch.
            internal sealed class B : IReduce
            {
                private readonly int m_n, m_k;

                internal B(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k >= 64 && (k & 63) == 0 && n - k >= 64);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    int w_k = k >> 6;

                    int pos = w_n;
                    do
                    {
                        ulong t = tt[ttOff + pos + w_n    ] >>  s_n
                                | tt[ttOff + pos + w_n + 1] << -s_n;

                        tt[ttOff + pos      ] ^= t;
                        tt[ttOff + pos + w_k] ^= t;
                    }
                    while (--pos >= 0);

                    Array.Copy(tt, ttOff, z, zOff, w_n);
                    z[zOff + w_n] = tt[ttOff + w_n] & ~(ulong.MaxValue << s_n);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    int w_k = k >> 6;

                    int pos = w_n;
                    do
                    {
                        ulong t = tt[pos + w_n    ] >>  s_n
                                | tt[pos + w_n + 1] << -s_n;

                        tt[pos      ] ^= t;
                        tt[pos + w_k] ^= t;
                    }
                    while (--pos >= 0);

                    tt.Slice(0, w_n).CopyTo(z);
                    z[w_n] = tt[w_n] & ~(ulong.MaxValue << s_n);
                }
#endif
            }

            // Sub-case C: word-at-a-time top-down fold, k >= 64 with (k & 63) != 0,
            // n - k >= 64, and w_n >= 4 (sizes 3 and 4 carved into C5 / C6 and C7 / C8
            // respectively). The "+x^k" tap straddles a word boundary so we splice via the
            // (t << -s_k) / (t >> -s_k) modular-shift idiom. Used by sect409 (n=409, k=87).
            internal sealed class C : IReduce
            {
                private readonly int m_n, m_k;

                internal C(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k >= 64 && (k & 63) != 0 && n - k >= 64 && n / 32 >= 8);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(w_n >= 4);

                    int pos = w_n;
                    do
                    {
                        ulong t = tt[ttOff + pos + w_n    ] >>  s_n
                                | tt[ttOff + pos + w_n + 1] << -s_n;

                        tt[ttOff + pos] ^= t;

                        tt[ttOff + pos + w_k    ] ^= t <<  s_k;
                        tt[ttOff + pos + w_k + 1] ^= t >> -s_k;
                    }
                    while (--pos >= 0);

                    Array.Copy(tt, ttOff, z, zOff, w_n);
                    z[zOff + w_n] = tt[ttOff + w_n] & ~(ulong.MaxValue << s_n);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(w_n >= 4);

                    int pos = w_n;
                    do
                    {
                        ulong t = tt[pos + w_n    ] >>  s_n
                                | tt[pos + w_n + 1] << -s_n;

                        tt[pos] ^= t;

                        tt[pos + w_k    ] ^= t <<  s_k;
                        tt[pos + w_k + 1] ^= t >> -s_k;
                    }
                    while (--pos >= 0);

                    tt.Slice(0, w_n).CopyTo(z);
                    z[w_n] = tt[w_n] & ~(ulong.MaxValue << s_n);
                }
#endif
            }

            // Sub-case C5: size-3 trinomials, slack subrange (n in [129, 159], so 2n - 1 <=
            // 317 and tt[5] is zero by the IReduce contract; the k >= 64 with (k & 63) != 0
            // and n - k >= 64 gates force k in [65, 95], hence w_k = 1). Fully unrolled,
            // tt[0..4] held in locals (5 limbs); the result is written directly to z[0..2]
            // (no tt staging buffer copy). No SECT trinomial hits this branch.
            internal sealed class C5 : IReduce
            {
                private readonly int m_n, m_k;

                internal C5(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k >= 64 && (k & 63) != 0 && n - k >= 64 && n / 32 == 4);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(w_n == 2);
                    Debug.Assert(w_k == 1);

                    // Load tt[0..4] into locals; tt[5] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2];
                    ulong t3 = tt[ttOff + 3], t4 = tt[ttOff + 4];

                    // Unrolled top-down word fold (pos = 2, 1, 0). With w_k = 1, the "+x^k"
                    // tap writes to tt[pos + 1] (low) and tt[pos + 2] (high). At pos = 2 the
                    // read simplifies because tt[5] = 0.
                    ulong t = t4 >> s_n;                    // pos = 2 (tt[5] is zero)
                    t2 ^= t;
                    t3 ^= t << s_k;
                    t4 ^= t >> -s_k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 1
                    t1 ^= t;
                    t2 ^= t << s_k;
                    t3 ^= t >> -s_k;

                    t = (t2 >> s_n) | (t3 << -s_n);         // pos = 0
                    t0 ^= t;
                    t1 ^= t << s_k;
                    t2 ^= t >> -s_k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    // Write the three result limbs directly to z, bypassing the tt staging copy.
                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(w_n == 2);
                    Debug.Assert(w_k == 1);

                    // Load tt[0..4] into locals; tt[5] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2];
                    ulong t3 = tt[3], t4 = tt[4];

                    // Unrolled top-down word fold (pos = 2, 1, 0). With w_k = 1, the "+x^k"
                    // tap writes to tt[pos + 1] (low) and tt[pos + 2] (high). At pos = 2 the
                    // read simplifies because tt[5] = 0.
                    ulong t = t4 >> s_n;                    // pos = 2 (tt[5] is zero)
                    t2 ^= t;
                    t3 ^= t << s_k;
                    t4 ^= t >> -s_k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 1
                    t1 ^= t;
                    t2 ^= t << s_k;
                    t3 ^= t >> -s_k;

                    t = (t2 >> s_n) | (t3 << -s_n);         // pos = 0
                    t0 ^= t;
                    t1 ^= t << s_k;
                    t2 ^= t >> -s_k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    // Write the three result limbs directly to z, bypassing the tt staging copy.
                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                }
#endif
            }

            // Sub-case C6: size-3 trinomials, non-slack subrange (n in [161, 191]; the slack
            // subrange n in [129, 159] is carved out into C5). The k >= 64 with (k & 63) != 0
            // and n - k >= 64 gates force k in [65, 127], hence w_k = 1. Fully unrolled,
            // tt[0..5] held in locals (6 limbs); the result is written directly to z[0..2]
            // (no tt staging buffer copy). No SECT trinomial hits this branch.
            internal sealed class C6 : IReduce
            {
                private readonly int m_n, m_k;

                internal C6(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k >= 64 && (k & 63) != 0 && n - k >= 64 && n / 32 == 5);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(w_n == 2);
                    Debug.Assert(w_k == 1);

                    // Load tt[0..5] into locals.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2];
                    ulong t3 = tt[ttOff + 3], t4 = tt[ttOff + 4], t5 = tt[ttOff + 5];

                    // Unrolled top-down word fold (pos = 2, 1, 0). With w_k = 1, the "+x^k"
                    // tap writes to tt[pos + 1] (low) and tt[pos + 2] (high).
                    ulong t = (t4 >> s_n) | (t5 << -s_n);   // pos = 2
                    t2 ^= t;
                    t3 ^= t << s_k;
                    t4 ^= t >> -s_k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 1
                    t1 ^= t;
                    t2 ^= t << s_k;
                    t3 ^= t >> -s_k;

                    t = (t2 >> s_n) | (t3 << -s_n);         // pos = 0
                    t0 ^= t;
                    t1 ^= t << s_k;
                    t2 ^= t >> -s_k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    // Write the three result limbs directly to z, bypassing the tt staging copy.
                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(w_n == 2);
                    Debug.Assert(w_k == 1);

                    // Load tt[0..5] into locals.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2];
                    ulong t3 = tt[3], t4 = tt[4], t5 = tt[5];

                    // Unrolled top-down word fold (pos = 2, 1, 0). With w_k = 1, the "+x^k"
                    // tap writes to tt[pos + 1] (low) and tt[pos + 2] (high).
                    ulong t = (t4 >> s_n) | (t5 << -s_n);   // pos = 2
                    t2 ^= t;
                    t3 ^= t << s_k;
                    t4 ^= t >> -s_k;

                    t = (t3 >> s_n) | (t4 << -s_n);         // pos = 1
                    t1 ^= t;
                    t2 ^= t << s_k;
                    t3 ^= t >> -s_k;

                    t = (t2 >> s_n) | (t3 << -s_n);         // pos = 0
                    t0 ^= t;
                    t1 ^= t << s_k;
                    t2 ^= t >> -s_k;

                    // Mask off bits above position n - 1 in the top result limb.
                    t2 &= ~(ulong.MaxValue << s_n);

                    // Write the three result limbs directly to z, bypassing the tt staging copy.
                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                }
#endif
            }

            // Sub-case C7: size-4 trinomials, slack subrange (n in [193, 223], so 2n - 1 <=
            // 445 and tt[7] is zero by the IReduce contract). Fully unrolled, tt[0..6] held
            // in locals (7 limbs); the body branches on w_k in {1, 2} (the "+x^k" tap's
            // destination limbs depend on w_k). The result is written directly to z[0..3]
            // (no tt staging buffer copy). No SECT trinomial hits this branch.
            internal sealed class C7 : IReduce
            {
                private readonly int m_n, m_k;

                internal C7(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k >= 64 && (k & 63) != 0 && n - k >= 64 && n / 32 == 6);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(w_n == 3);
                    Debug.Assert(w_k == 1 || w_k == 2);

                    // Load tt[0..6] into locals; tt[7] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2], t3 = tt[ttOff + 3];
                    ulong t4 = tt[ttOff + 4], t5 = tt[ttOff + 5], t6 = tt[ttOff + 6];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0). At pos = 3 the read
                    // simplifies because tt[7] = 0. The destinations of the "+x^k" tap
                    // depend on w_k (in {1, 2}), so the body branches once on w_k and
                    // inlines the destinations in each arm.
                    if (w_k == 1)
                    {
                        ulong t = t6 >> s_n;                    // pos = 3 (tt[7] is zero)
                        t3 ^= t;
                        t4 ^= t << s_k;
                        t5 ^= t >> -s_k;

                        t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                        t2 ^= t;
                        t3 ^= t << s_k;
                        t4 ^= t >> -s_k;

                        t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                        t1 ^= t;
                        t2 ^= t << s_k;
                        t3 ^= t >> -s_k;

                        t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                        t0 ^= t;
                        t1 ^= t << s_k;
                        t2 ^= t >> -s_k;
                    }
                    else // w_k == 2
                    {
                        ulong t = t6 >> s_n;                    // pos = 3 (tt[7] is zero)
                        t3 ^= t;
                        t5 ^= t << s_k;
                        t6 ^= t >> -s_k;

                        t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                        t2 ^= t;
                        t4 ^= t << s_k;
                        t5 ^= t >> -s_k;

                        t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                        t1 ^= t;
                        t3 ^= t << s_k;
                        t4 ^= t >> -s_k;

                        t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                        t0 ^= t;
                        t2 ^= t << s_k;
                        t3 ^= t >> -s_k;
                    }

                    // Mask off bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    // Write the four result limbs directly to z, bypassing the tt staging copy.
                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                    z[zOff + 3] = t3;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(w_n == 3);
                    Debug.Assert(w_k == 1 || w_k == 2);

                    // Load tt[0..6] into locals; tt[7] is slack (= 0 by contract) and elided.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2], t3 = tt[3];
                    ulong t4 = tt[4], t5 = tt[5], t6 = tt[6];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0). At pos = 3 the read
                    // simplifies because tt[7] = 0. The destinations of the "+x^k" tap
                    // depend on w_k (in {1, 2}), so the body branches once on w_k and
                    // inlines the destinations in each arm.
                    if (w_k == 1)
                    {
                        ulong t = t6 >> s_n;                    // pos = 3 (tt[7] is zero)
                        t3 ^= t;
                        t4 ^= t << s_k;
                        t5 ^= t >> -s_k;

                        t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                        t2 ^= t;
                        t3 ^= t << s_k;
                        t4 ^= t >> -s_k;

                        t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                        t1 ^= t;
                        t2 ^= t << s_k;
                        t3 ^= t >> -s_k;

                        t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                        t0 ^= t;
                        t1 ^= t << s_k;
                        t2 ^= t >> -s_k;
                    }
                    else // w_k == 2
                    {
                        ulong t = t6 >> s_n;                    // pos = 3 (tt[7] is zero)
                        t3 ^= t;
                        t5 ^= t << s_k;
                        t6 ^= t >> -s_k;

                        t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                        t2 ^= t;
                        t4 ^= t << s_k;
                        t5 ^= t >> -s_k;

                        t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                        t1 ^= t;
                        t3 ^= t << s_k;
                        t4 ^= t >> -s_k;

                        t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                        t0 ^= t;
                        t2 ^= t << s_k;
                        t3 ^= t >> -s_k;
                    }

                    // Mask off bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    // Write the four result limbs directly to z, bypassing the tt staging copy.
                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                    z[3] = t3;
                }
#endif
            }

            // Sub-case C8: size-4 trinomials, non-slack subrange (n in [225, 255]; the slack
            // subrange n in [193, 223] is carved out into C7). Fully unrolled, tt[0..7] held
            // in locals (8 limbs); the body branches on w_k in {1, 2} (the "+x^k" tap's
            // destination limbs depend on w_k). The result is written directly to z[0..3]
            // (no tt staging buffer copy). Used by sect233 (n=233, w_k=1), sect239 (n=239,
            // w_k=2).
            internal sealed class C8 : IReduce
            {
                private readonly int m_n, m_k;

                internal C8(int n, int k)
                {
                    Debug.Assert((n & 63) != 0 && k >= 64 && (k & 63) != 0 && n - k >= 64 && n / 32 == 7);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(w_n == 3);
                    Debug.Assert(w_k == 1 || w_k == 2);

                    // Load tt[0..7] into locals so the JIT can keep the fold state in registers.
                    ulong t0 = tt[ttOff], t1 = tt[ttOff + 1], t2 = tt[ttOff + 2], t3 = tt[ttOff + 3];
                    ulong t4 = tt[ttOff + 4], t5 = tt[ttOff + 5], t6 = tt[ttOff + 6], t7 = tt[ttOff + 7];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0). Each iteration:
                    //   t            = (tt[pos+3] >> s_n) | (tt[pos+4] << -s_n)
                    //   tt[pos]      ^= t                                          (+1 tap)
                    //   tt[pos+w_k]  ^= t << s_k                                   (+x^k low)
                    //   tt[pos+w_k+1]^= t >> -s_k                                  (+x^k high)
                    // The destinations of the +x^k tap depend on w_k (in {1, 2}), so the body
                    // branches once on w_k and inlines the destinations in each arm.
                    if (w_k == 1)
                    {
                        ulong t = (t6 >> s_n) | (t7 << -s_n);   // pos = 3
                        t3 ^= t;
                        t4 ^= t << s_k;
                        t5 ^= t >> -s_k;

                        t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                        t2 ^= t;
                        t3 ^= t << s_k;
                        t4 ^= t >> -s_k;

                        t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                        t1 ^= t;
                        t2 ^= t << s_k;
                        t3 ^= t >> -s_k;

                        t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                        t0 ^= t;
                        t1 ^= t << s_k;
                        t2 ^= t >> -s_k;
                    }
                    else // w_k == 2
                    {
                        ulong t = (t6 >> s_n) | (t7 << -s_n);   // pos = 3
                        t3 ^= t;
                        t5 ^= t << s_k;
                        t6 ^= t >> -s_k;

                        t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                        t2 ^= t;
                        t4 ^= t << s_k;
                        t5 ^= t >> -s_k;

                        t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                        t1 ^= t;
                        t3 ^= t << s_k;
                        t4 ^= t >> -s_k;

                        t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                        t0 ^= t;
                        t2 ^= t << s_k;
                        t3 ^= t >> -s_k;
                    }

                    // Mask off the bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    // Write the four result limbs directly to z, bypassing the tt staging copy.
                    z[zOff] = t0;
                    z[zOff + 1] = t1;
                    z[zOff + 2] = t2;
                    z[zOff + 3] = t3;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    Pos(n, out int w_n, out int s_n);
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(w_n == 3);
                    Debug.Assert(w_k == 1 || w_k == 2);

                    // Load tt[0..7] into locals so the JIT can keep the fold state in registers.
                    ulong t0 = tt[0], t1 = tt[1], t2 = tt[2], t3 = tt[3];
                    ulong t4 = tt[4], t5 = tt[5], t6 = tt[6], t7 = tt[7];

                    // Unrolled top-down word fold (pos = 3, 2, 1, 0). Each iteration:
                    //   t            = (tt[pos+3] >> s_n) | (tt[pos+4] << -s_n)
                    //   tt[pos]      ^= t                                          (+1 tap)
                    //   tt[pos+w_k]  ^= t << s_k                                   (+x^k low)
                    //   tt[pos+w_k+1]^= t >> -s_k                                  (+x^k high)
                    // The destinations of the +x^k tap depend on w_k (in {1, 2}), so the body
                    // branches once on w_k and inlines the destinations in each arm.
                    if (w_k == 1)
                    {
                        ulong t = (t6 >> s_n) | (t7 << -s_n);   // pos = 3
                        t3 ^= t;
                        t4 ^= t << s_k;
                        t5 ^= t >> -s_k;

                        t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                        t2 ^= t;
                        t3 ^= t << s_k;
                        t4 ^= t >> -s_k;

                        t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                        t1 ^= t;
                        t2 ^= t << s_k;
                        t3 ^= t >> -s_k;

                        t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                        t0 ^= t;
                        t1 ^= t << s_k;
                        t2 ^= t >> -s_k;
                    }
                    else // w_k == 2
                    {
                        ulong t = (t6 >> s_n) | (t7 << -s_n);   // pos = 3
                        t3 ^= t;
                        t5 ^= t << s_k;
                        t6 ^= t >> -s_k;

                        t = (t5 >> s_n) | (t6 << -s_n);         // pos = 2
                        t2 ^= t;
                        t4 ^= t << s_k;
                        t5 ^= t >> -s_k;

                        t = (t4 >> s_n) | (t5 << -s_n);         // pos = 1
                        t1 ^= t;
                        t3 ^= t << s_k;
                        t4 ^= t >> -s_k;

                        t = (t3 >> s_n) | (t4 << -s_n);         // pos = 0
                        t0 ^= t;
                        t2 ^= t << s_k;
                        t3 ^= t >> -s_k;
                    }

                    // Mask off the bits above position n - 1 in the top result limb.
                    t3 &= ~(ulong.MaxValue << s_n);

                    // Write the four result limbs directly to z, bypassing the tt staging copy.
                    z[0] = t0;
                    z[1] = t1;
                    z[2] = t2;
                    z[3] = t3;
                }
#endif
            }

            // Sub-case D: bit-by-bit top-down fold. Handles cases the word-at-a-time bodies
            // cannot: (a) n - k < 64, where the "+x^k" contribution from the lowest iteration of a
            // word-at-a-time fold could spill back above position n; and (b) the residual
            // (n & 63) == 0 cases not taken by E (k a multiple of 64, or n - k < 64), where those
            // bodies' (t << -s) idiom and final mask break at s_n = 0. The fold is parity-agnostic,
            // and the final write skips the partial-limb mask when s_top == 0. No SECT trinomial
            // hits this branch; it is correctness-defensive for arbitrary (n, k) supplied via the
            // future F2mFieldElement replacement.
            internal sealed class D : IReduce
            {
                private readonly int m_n, m_k;

                internal D(int n, int k)
                {
                    Debug.Assert(n - k < 64 || ((n & 63) == 0 && (k & 63) == 0));
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);

                    int pos_0 = n - 1;
                    while (--pos_0 >= 0)
                    {
                        Pos(pos_0 + n, out int w_n, out int s_n);
                        ulong bit_n = (tt[ttOff + w_n] >> s_n) & 1UL;

                        Pos(pos_0, out int w_0, out int s_0);
                        tt[ttOff + w_0] ^= bit_n << s_0;

                        Pos(pos_0 + k, out int w_k, out int s_k);
                        tt[ttOff + w_k] ^= bit_n << s_k;
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
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);

                    int pos_0 = n - 1;
                    while (--pos_0 >= 0)
                    {
                        Pos(pos_0 + n, out int w_n, out int s_n);
                        ulong bit_n = (tt[w_n] >> s_n) & 1UL;

                        Pos(pos_0, out int w_0, out int s_0);
                        tt[w_0] ^= bit_n << s_0;

                        Pos(pos_0 + k, out int w_k, out int s_k);
                        tt[w_k] ^= bit_n << s_k;
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

            // Sub-case E: word-aligned n ((n & 63) == 0), with (k & 63) != 0 and n - k >= 64. The
            // word-aligned analogue of C: with s_n == 0 the "+1" read needs no cross-word splice,
            // so t is just the high word tt[pos + W] read directly, and the result is W = n / 64
            // full limbs (no partial top limb to mask). The dispatch preconditions force
            // w_k <= W - 2, so the "+x^k" splice writes only to limbs strictly below the current
            // high word (pos + W) -- the single top-down sweep folds every high limb without
            // re-reading. No SECT trinomial hits this branch; it is correctness-defensive for
            // arbitrary (n, k) supplied via the future F2mFieldElement replacement.
            internal sealed class E : IReduce
            {
                private readonly int m_n, m_k;

                internal E(int n, int k)
                {
                    Debug.Assert((n & 63) == 0 && (k & 63) != 0 && n - k >= 64);
                    m_n = n;
                    m_k = k;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt, ttOff);
                    int W = n >> 6;
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(s_k != 0 && w_k <= W - 2);

                    int pos = W - 1;
                    do
                    {
                        ulong t = tt[ttOff + pos + W];

                        tt[ttOff + pos] ^= t;

                        tt[ttOff + pos + w_k    ] ^= t <<  s_k;
                        tt[ttOff + pos + w_k + 1] ^= t >> -s_k;
                    }
                    while (--pos >= 0);

                    Array.Copy(tt, ttOff, z, zOff, W);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n, k = m_k;
                    DebugAssertReducePreconditions(n, tt);
                    int W = n >> 6;
                    Pos(k, out int w_k, out int s_k);
                    Debug.Assert(s_k != 0 && w_k <= W - 2);

                    int pos = W - 1;
                    do
                    {
                        ulong t = tt[pos + W];

                        tt[pos] ^= t;

                        tt[pos + w_k    ] ^= t <<  s_k;
                        tt[pos + w_k + 1] ^= t >> -s_k;
                    }
                    while (--pos >= 0);

                    tt.Slice(0, W).CopyTo(z);
                }
#endif
            }
        }
    }
}
