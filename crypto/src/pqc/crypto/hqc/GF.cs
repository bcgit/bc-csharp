namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    /**
     * Arithmetic in GF(2^8) = GF(2)[X]/(X^8 + X^4 + X^3 + X + 1), the field underlying HQC's Reed-Solomon code (HQC
     * specification of 2026-10-12, Section 2.1; the 2025-08-22 specification used X^8 + X^4 + X^3 + X^2 + 1, so the
     * Reed-Solomon generator polynomials and the alpha power tables in <see cref="ReedSolomon"/> changed with it).
     * <p>
     * NOTE: every operation here is table-free and branch-free on purpose. These routines run on secret-derived
     * values on both sides of the KEM - <see cref="ReedSolomon.Encode"/> multiplies by coefficients derived from the
     * secret message during encapsulation, and <see cref="ReedSolomon.Decode"/> plus
     * <see cref="FastFourierTransform"/> operate on syndromes, error locator coefficients and root sets derived from
     * the secret error vector during decapsulation. An earlier version of this class used log/exp/inv/sqr lookup
     * tables indexed by those values, so which cache line was touched revealed the secret: the same
     * secret-dependent-memory-access weakness as an AES T-table implementation. Do not reintroduce a table indexed by
     * a field element, and do not add early exits or data-dependent branches.
     * </p>
     * <p>
     * The field is the one AES uses: the multiplication follows <c>Org.BouncyCastle.Math.Raw.GF256Aes</c>, and the
     * squaring uses the same reduction constants, but HQC keeps its own copy so that the two stay independent.
     * </p>
     */
    internal static class GF
    {
        internal static int Div(int a, int b) => Mul(a, Inv(b));

        internal static int Inv(int a)
        {
            // a^254 = a^-1 for a != 0, since a^255 = 1; and 0^254 = 0, matching the inverse of zero being defined as
            // zero here. Addition chain 2, 4, 8, 6, 14, 28, 56, 112, 126, 252, 254: seven squarings and four
            // multiplications, all of them constant-time.
            a &= 0xFF;
            int a2 = Sqr(a);
            int a4 = Sqr(a2);
            int a8 = Sqr(a4);
            int a6 = Mul(a4, a2);
            int a14 = Mul(a8, a6);
            int a28 = Sqr(a14);
            int a56 = Sqr(a28);
            int a112 = Sqr(a56);
            int a126 = Mul(a112, a14);
            int a252 = Sqr(a126);
            return Mul(a252, a2);
        }

        internal static int Mul(int a, int b)
        {
            b &= 0xFF;

            // carryless multiply: each bit of a selects, by mask, a shifted copy of b. A zero operand needs no
            // special case, it simply selects nothing and leaves the product zero. The partial products of the high
            // nibble of a (bits 4 to 14) and of the low nibble (bits 0 to 10) are kept apart so that each can be
            // reduced with a single fold.
            int c = (b << 4) & -(a & 0x10)
                  ^ (b << 5) & -(a & 0x20)
                  ^ (b << 6) & -(a & 0x40)
                  ^ (b << 7) & -(a & 0x80);
            int d = (b << 0) & -(a & 0x01)
                  ^ (b << 1) & -(a & 0x02)
                  ^ (b << 2) & -(a & 0x04)
                  ^ (b << 3) & -(a & 0x08);

            // reduce: X^8 = X^4 + X^3 + X + 1 (0x1B), and multiplying by 0x1B is e ^= e << 1 (X + 1) then
            // e ^= e << 3 (X^3 + 1). Fold the bits of c above X^7 into d; then take the bits of d above X^7 aside,
            // add in the low byte of c (its bits 4 to 7), and fold the bits taken aside.
            int e = c >> 8;
            e ^= e << 1;
            e ^= e << 3;
            d ^= e;

            int f = d >> 8;
            d = (d ^ c) & 0xFF;
            f ^= f << 1;
            f ^= f << 3;
            d ^= f;

            return d;
        }

        internal static int Mul3(int a, int b, int c) => Mul(Mul(a, b), c);

        internal static int Sqr(int a)
        {
            // squaring is linear over GF(2): spreading the bits of a to the even positions yields a(X)^2 directly,
            // there are no cross terms to accumulate. The low nibble spreads into the low byte; the high nibble's
            // squares X^8, X^10, X^12 and X^14 are added already reduced (0x1B, 0x6C, 0xAB and 0x9A).
            int x = a & 0x0F;
            x = (x | (x << 2)) & 0x33;
            x = (x | (x << 1)) & 0x55;

            int hi = 0x1B & -((a >> 4) & 1)
                   ^ 0x6C & -((a >> 5) & 1)
                   ^ 0xAB & -((a >> 6) & 1)
                   ^ 0x9A & -((a >> 7) & 1);

            return x ^ hi;
        }
    }
}
