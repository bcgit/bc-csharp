using NUnit.Framework;

using Org.BouncyCastle.Pqc.Crypto.Hqc;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    /**
     * Tests for HQC's GF(2^8) arithmetic.
     * <p>
     * <see cref="GF"/> forwards to <c>GF256Aes</c>, whose arithmetic is tested exhaustively in <c>GF256AesTest</c>.
     * These tests pin what is HQC's own: that the field is the one of the HQC specification of 2026-10-12, and that
     * the composition <see cref="GF.Div"/> is right, including on zero.
     * </p>
     */
    [TestFixture]
    public class HqcGFTest
    {
        /**
         * The reduction X^8 = X^4 + X^3 + X + 1, and the opening entries of the reference implementation's gf_exp,
         * the powers of the generator X + 1, which must have order 255 (X alone is not primitive in this field, its
         * order is 51).
         */
        [Test]
        public void FieldIsTheSpecField()
        {
            Assert.AreEqual(0x1B, GF.Mul(0x80, 0x02), "X^7 * X");

            int[] expected = { 1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53 };
            int x = 1;
            for (int i = 0; i < expected.Length; ++i)
            {
                Assert.AreEqual(expected[i], x, "gf_exp[" + i + "]");
                x = GF.Mul(x, 0x03);
            }

            x = 1;
            for (int i = 1; i <= 255; ++i)
            {
                x = GF.Mul(x, 0x03);
                Assert.AreEqual(i == 255, x == 1, "(X + 1)^" + i + " == 1");
            }
        }

        [Test]
        public void DivInvertsMul()
        {
            for (int a = 0; a < 256; ++a)
            {
                // the inverse of zero is defined as zero, so division by zero yields zero
                Assert.AreEqual(0, GF.Div(a, 0), "div(" + a + ",0)");

                for (int b = 1; b < 256; ++b)
                {
                    int q = GF.Div(a, b);
                    Assert.IsTrue(q >= 0 && q < 256, "div(" + a + "," + b + ") out of range: " + q);
                    Assert.AreEqual(a, GF.Mul(q, b), "mul(div(a,b),b) for a=" + a + " b=" + b);
                }
            }
        }
    }
}
