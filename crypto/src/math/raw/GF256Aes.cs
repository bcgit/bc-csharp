namespace Org.BouncyCastle.Math.Raw
{
    /// <summary>
    /// Constant-time arithmetic in GF(2^8) = GF(2)[X]/(X^8 + X^4 + X^3 + X + 1), the AES field (polynomial
    /// <c>0x11B</c>), with elements in the polynomial basis as integers 0..255.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every operation is safe on secret values, and callers depend on that (e.g. HQC's Reed-Solomon code runs on
    /// secret-derived syndromes and error locators). Nothing here may index a table by a field element, branch on
    /// one, or exit early: lookup tables leak through cache-line selection, as AES T-tables do.
    /// </para>
    /// <para>
    /// The <c>Aes</c> suffix names the reduction polynomial, not just the field: GF(2^8) has other representations
    /// (other polynomials, tower bases) whose products differ, and they must not share this class.
    /// </para>
    /// <para>
    /// Only the low 8 bits of each argument are used; results are in 0..255.
    /// </para>
    /// </remarks>
    internal static class GF256Aes
    {
        /// <summary>Product <c>a * b</c>.</summary>
        internal static int Mul(int a, int b)
        {
            b &= 0xFF;

            // Carryless multiply: each bit of a selects, by mask, a shifted copy of b, so a zero operand needs no
            // special case. The partial products for the high nibble of a (c, bits 4 to 14) and for the low nibble
            // (d, bits 0 to 10) are accumulated separately.
            int c = (b << 4) & -(a & 0x10)
                  ^ (b << 5) & -(a & 0x20)
                  ^ (b << 6) & -(a & 0x40)
                  ^ (b << 7) & -(a & 0x80);
            int d = (b << 0) & -(a & 0x01)
                  ^ (b << 1) & -(a & 0x02)
                  ^ (b << 2) & -(a & 0x04)
                  ^ (b << 3) & -(a & 0x08);

            // Reduce with X^8 = X^4 + X^3 + X + 1 (0x1B); multiplying by 0x1B = (X + 1)(X^3 + 1) is e ^= e << 1
            // then e ^= e << 3. First fold c's bits above X^7 into d, landing at or below X^10...
            int e = c >> 8;
            e ^= e << 1;
            e ^= e << 3;
            d ^= e;

            // ...then set d's bits above X^7 aside, add in the low byte of c (its bits 4 to 7), and fold them.
            int f = d >> 8; d = (d ^ c) & 0xFF;
            f ^= f << 1;
            f ^= f << 3;
            d ^= f;

            return d;
        }

        /// <summary>Square <c>a * a</c>.</summary>
        internal static int Sqr(int a)
        {
            // Squaring is linear over GF(2): a(X)^2 is the sum of a_i X^(2i), with no cross terms.

            // Spread the low nibble to the even bit positions. No PDEP (Bmi2.ParallelBitDeposit) here: for 4 bits it
            // gains nothing over the two shift-and-mask steps, and it is microcoded and slow on AMD Zen 1/2.
            int c = a & 0x0F;
            c = (c | (c << 2)) & 0x33;
            c = (c | (c << 1)) & 0x55;

            // The high nibble's squares X^8, X^10, X^12 and X^14 are added already reduced (0x1B, 0x6C, 0xAB and
            // 0x9A). The constants sit 8 bits up so that each mask -(a & 0x10) .. -(a & 0x80), all ones from its bit
            // upward, covers them without first shifting the bit down.
            int hi = 0x1B00 & -(a & 0x10)
                   ^ 0x6C00 & -(a & 0x20)
                   ^ 0xAB00 & -(a & 0x40)
                   ^ 0x9A00 & -(a & 0x80);
            return c ^ (hi >> 8);
        }

        /// <summary>Inverse <c>a^-1</c>, computed as <c>a^254</c>, so the inverse of 0 is 0.</summary>
        internal static int Inv(int a)
        {
            // a^254 = a^-1 for a != 0, since a^255 = 1; and 0^254 = 0. Addition chain 2, 4, 8, 6, 14, 28, 56, 112,
            // 126, 252, 254: seven squarings and four multiplications.
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
    }
}
