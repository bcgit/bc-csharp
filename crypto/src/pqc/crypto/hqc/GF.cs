using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    /**
     * Arithmetic in GF(2^8) = GF(2)[X]/(X^8 + X^4 + X^3 + X + 1), the field underlying HQC's Reed-Solomon code (HQC
     * specification of 2026-10-12, Section 2.1; the 2025-08-22 specification used X^8 + X^4 + X^3 + X^2 + 1, so the
     * Reed-Solomon generator polynomials and the alpha power tables in <see cref="ReedSolomon"/> changed with it).
     * This is the AES field, so the arithmetic is <see cref="GF256Aes"/>'s.
     * <p>
     * NOTE: these routines run on secret-derived values on both sides of the KEM - <see cref="ReedSolomon.Encode"/>
     * multiplies by coefficients derived from the secret message during encapsulation, and
     * <see cref="ReedSolomon.Decode"/> plus <see cref="FastFourierTransform"/> operate on syndromes, error locator
     * coefficients and root sets derived from the secret error vector during decapsulation. An earlier version of this
     * class used log/exp/inv/sqr lookup tables indexed by those values, so which cache line was touched revealed the
     * secret. <see cref="GF256Aes"/> guarantees table-free, branch-free operations; anything added here must only
     * compose them.
     * </p>
     */
    internal static class GF
    {
        internal static int Div(int a, int b) => GF256Aes.Mul(a, GF256Aes.Inv(b));

        internal static int Inv(int a) => GF256Aes.Inv(a);

        internal static int Mul(int a, int b) => GF256Aes.Mul(a, b);

        internal static int Sqr(int a) => GF256Aes.Sqr(a);
    }
}
