using System;
using System.Diagnostics;

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Math.BinPoly
{
    internal abstract partial class BinPolyMulBase
    {
        // Reduction by x^n + 1. The factory selects Unaligned for the common case
        // ((n & 63) != 0, partial top limb) or Aligned for n a multiple of 64 (full top
        // limb, word-aligned fold).
        internal static class BinomialReduce
        {
            internal static IReduce Create(int n)
            {
                if ((n & 63) == 0)
                    return new Aligned(n);

                return new Unaligned(n);
            }

            // Sub-case Unaligned: (n & 63) != 0, so the top result limb is partial. Folds the
            // high half up by excessBits = -n & 63 and masks the partial top limb.
            internal sealed class Unaligned : IReduce
            {
                private readonly int m_n;

                internal Unaligned(int n)
                {
                    Debug.Assert((n & 63) != 0);
                    m_n = n;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n;
                    DebugAssertReducePreconditions(n, tt, ttOff);

                    int last = n >> 6, size = last + 1;
                    int excessBits = -n & 63;

                    ulong c = Nat.ShiftUpBitsXor64(size, tt, ttOff + size, excessBits, tt[ttOff + last], tt, ttOff,
                        z, zOff);
                    Debug.Assert(c == 0UL);
                    z[zOff + last] &= ulong.MaxValue >> excessBits;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n;
                    DebugAssertReducePreconditions(n, tt);

                    int last = n >> 6, size = last + 1;
                    int excessBits = -n & 63;

                    ulong c = Nat.ShiftUpBitsXor64(size, tt.Slice(size), excessBits, tt[last], tt, z);
                    Debug.Assert(c == 0UL);
                    z[last] &= ulong.MaxValue >> excessBits;
                }
#endif
            }

            // Sub-case Aligned: n a multiple of 64. The ring period is word-aligned, so x^n ≡ 1
            // folds limb-for-limb with no shift or mask: z = low ^ high over size = n / 64 limbs.
            // There is no partial top limb, so Unaligned's final-mask / cross-word logic does not
            // apply (and would index one limb past z).
            internal sealed class Aligned : IReduce
            {
                private readonly int m_n;

                internal Aligned(int n)
                {
                    Debug.Assert((n & 63) == 0);
                    m_n = n;
                }

                public void Reduce(ulong[] tt, int ttOff, ulong[] z, int zOff)
                {
                    int n = m_n;
                    DebugAssertReducePreconditions(n, tt, ttOff);

                    int size = n >> 6;
                    Nat.Xor64(size, tt, ttOff, tt, ttOff + size, z, zOff);
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                public void Reduce(Span<ulong> tt, Span<ulong> z)
                {
                    int n = m_n;
                    DebugAssertReducePreconditions(n, tt);

                    int size = n >> 6;
                    Nat.Xor64(size, tt, tt.Slice(size), z);
                }
#endif
            }
        }
    }
}
