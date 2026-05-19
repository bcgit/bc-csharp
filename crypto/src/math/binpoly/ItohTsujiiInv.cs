using System.Diagnostics;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.BinPoly
{
    /// <summary>
    /// Itoh–Tsujii multiplicative inversion in <c>GF(2^n)</c>: computes
    /// <c>a^{-1} = a^(2^n - 2) = (a^(2^(n-1) - 1))^2</c> using a generic binary addition chain on
    /// the exponent <c>e = n - 1</c>, driving the supplied <see cref="IBinPolyMul"/>'s
    /// <c>Multiply</c> / <c>Square</c> / <c>SquareN</c> (so it is backend-independent — one
    /// implementation serves every ISA).
    /// </summary>
    /// <remarks>
    /// <para>Let <c>a_k = a^(2^k - 1)</c> (the element whose exponent is <c>k</c> one-bits). Then
    /// <c>a_1 = a</c>, and the chain walks the bits of <c>e = n - 1</c> from the bit below the MSB
    /// down to bit 0, applying:</para>
    /// <list type="bullet">
    /// <item><description><b>double</b> (<c>k -&gt; 2k</c>): <c>a_{2k} = (a_k)^(2^k) * a_k</c> — one
    /// <c>SquareN(., k)</c> then one <c>Multiply</c>;</description></item>
    /// <item><description><b>increment</b> (<c>k -&gt; k+1</c>, when the bit is set):
    /// <c>a_{k+1} = (a_k)^2 * a</c> — one <c>Square</c> then one <c>Multiply</c>.</description></item>
    /// </list>
    /// <para>After the chain <c>b = a^(2^(n-1) - 1)</c>; one final <c>Square</c> gives
    /// <c>a^(2^n - 2)</c>. The element value never steers control flow: <c>0</c> and <c>1</c> are
    /// fixed points of the primitives, so <c>Invert(0) = 0</c> and <c>Invert(1) = 1</c> fall out of
    /// the unconditional chain with no special case (constant-time-friendly). Correct only for an
    /// irreducible reduction polynomial — see <see cref="IBinPolyInv"/>.</para>
    /// <para>Parity of <c>n</c> needs no special case: the chain is on <c>e = n - 1</c>, so <c>n</c>
    /// merely decides whether the first step is a double (<c>n</c> odd) or an increment
    /// (<c>n</c> even).</para>
    /// </remarks>
    internal sealed class ItohTsujiiInv
        : IBinPolyInv
    {
        private readonly IBinPolyMul m_mul;
        private readonly int m_n;
        private readonly int m_size;

        internal ItohTsujiiInv(IBinPolyMul mul)
        {
            // A field needs n >= 2 (n == 1 is the degenerate GF(2)); the field factories
            // (Trinomial n >= 3, Pentanomial n >= 5) always satisfy this.
            Debug.Assert(mul.N >= 2);
            m_mul = mul;
            m_n = mul.N;
            m_size = mul.Size;
        }

        public int N => m_n;
        public int Size => m_size;

        public void Invert(ulong[] x, int xOff, ulong[] z, int zOff)
        {
            int n = m_n, size = m_size;
            IBinPolyMul mul = m_mul;

            // b accumulates a_j = a^(2^j - 1); j is the current run length of one-bits.
            // t holds the Frobenius power (a_j)^(2^j) used by the "double" step.
            ulong[] b = new ulong[size];
            ulong[] t = new ulong[size];
            try
            {
                BinPolys.Copy(size, x, xOff, b, 0);    // b = a = a_1

                // Walk e = n - 1 from the bit below the MSB (the MSB is the seed j = 1) down to 0.
                int e = n - 1;
                int j = 1;
                for (int i = Integers.BitLength(e) - 2; i >= 0; --i)
                {
                    // double: a_{2j} = (a_j)^(2^j) * a_j
                    mul.SquareN(b, 0, j, t, 0);     // t = b^(2^j)
                    mul.Multiply(b, 0, t, 0, b, 0); // b = b * t   (x aliases z: allowed; y = t: distinct)
                    j <<= 1;

                    // Branch on e (= n - 1, the public field degree) -- never on element data --
                    // so the chain shape is fixed per field and this stays constant-time in the secret.
                    if (IsBitSet(e, i))
                    {
                        // increment: a_{j+1} = (a_j)^2 * a
                        mul.Square(b, 0, b, 0);             // b = b^2  (in-place: allowed)
                        mul.Multiply(b, 0, x, xOff, b, 0);  // b = b * a (y = a: distinct from b)
                        j += 1;
                    }
                }
                Debug.Assert(j == e);

                // DEBUG-only: verify a * a^{-1} == 1 (or a == 0) from b and the original input,
                // before z is written -- safe even when x aliases z.
                DebugAssertInverse(x, xOff, b);

                // a^{-1} = (a^(2^(n-1) - 1))^2 = a^(2^n - 2). Written last, so x may alias z.
                mul.Square(b, 0, z, zOff);
            }
            finally
            {
                BinPolys.Clear(size, b, 0);
                BinPolys.Clear(size, t, 0);
            }
        }

        private static bool IsBitSet(int value, int bit) => (value & (1 << bit)) != 0;

        // DEBUG-only self-check that the inverse about to be produced is correct: with inv = b^2,
        // the product a * inv = a^(2^n - 1) is 1 for a != 0 and 0 for a == 0. Reads only a and b,
        // so it does not depend on z (alias-safe).
        [Conditional("DEBUG")]
        private void DebugAssertInverse(ulong[] a, int aOff, ulong[] b)
        {
            int size = m_size;
            IBinPolyMul mul = m_mul;

            ulong[] product = new ulong[size];
            try
            {
                mul.Square(b, 0, product, 0);                   // product = b^2 = inv
                mul.Multiply(product, 0, a, aOff, product, 0);  // product = a * inv

                bool ok = BinPolys.EqualToZero(size, a, aOff) != 0
                    ? BinPolys.EqualToZero(size, product, 0) != 0   // a == 0 -> product 0
                    : BinPolys.EqualToOne(size, product, 0) != 0;   // a != 0 -> product 1

                Debug.Assert(ok, "Itoh-Tsujii inverse self-check failed");
            }
            finally
            {
                BinPolys.Clear(size, product, 0);
            }
        }
    }
}
