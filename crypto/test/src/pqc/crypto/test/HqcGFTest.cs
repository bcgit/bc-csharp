using NUnit.Framework;

using Org.BouncyCastle.Pqc.Crypto.Hqc;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    /**
     * Regression tests for HQC's GF(2^8) arithmetic.
     * <p>
     * <see cref="GF"/> used to be implemented with log/exp/inv/sqr lookup tables indexed by field elements, which
     * leaked secret-derived values through the cache; it is now table-free and branch-free. These tests pin the
     * arithmetic to the values the tables produced, so a future change cannot alter a result while the HQC
     * known-answer tests happen to keep passing on the subset of inputs they exercise.
     * </p>
     * <p>
     * The expected values come from an independent construction: log and exp tables built here by iterating the
     * generator X + 1 over GF(2)[X]/(X^8 + X^4 + X^3 + X + 1), the field of the HQC specification of 2026-10-12 (X
     * alone is not primitive in this field, its order is 51), so the oracle takes a different computational route
     * (discrete logs) from the implementation (carryless multiply and reduce). Field laws are checked as well, in
     * case both sides were to be wrong the same way.
     * </p>
     */
    [TestFixture]
    public class HqcGFTest
    {
        private const int Modulus = 0x11B;
        private const int Order = 255;

        private static readonly int[] Exp = new int[Order];
        private static readonly int[] Log = new int[256];

        static HqcGFTest()
        {
            int x = 1;
            for (int i = 0; i < Order; ++i)
            {
                Exp[i] = x;
                Log[x] = i;

                // multiply by the generator X + 1
                int t = (x << 1) ^ x;
                if ((t & 0x100) != 0)
                {
                    t ^= Modulus;
                }
                x = t & 0xFF;
            }
        }

        private static int OracleMul(int a, int b)
        {
            if (a == 0 || b == 0)
                return 0;

            return Exp[(Log[a] + Log[b]) % Order];
        }

        private static int OracleInv(int a)
        {
            if (a == 0)
                return 0;

            return Exp[(Order - Log[a]) % Order];
        }

        /**
         * Guard the oracle itself: these are the opening entries of the exp table for this field polynomial and
         * generator (the reference implementation's gf_exp), and the cycle must close back on 1.
         */
        [Test]
        public void OracleIsTheExpectedField()
        {
            int[] expected = { 1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53 };
            for (int i = 0; i < expected.Length; ++i)
            {
                Assert.AreEqual(expected[i], Exp[i], "exp[" + i + "]");
            }

            // exp is a bijection onto the 255 non-zero elements, and log inverts it
            bool[] seen = new bool[256];
            for (int i = 0; i < Order; ++i)
            {
                Assert.AreNotEqual(0, Exp[i], "exp[" + i + "] is zero");
                Assert.IsFalse(seen[Exp[i]], "exp repeats " + Exp[i]);
                seen[Exp[i]] = true;
                Assert.AreEqual(i, Log[Exp[i]], "log(exp(" + i + "))");
            }
        }

        [Test]
        public void MulAgainstOracle()
        {
            for (int a = 0; a < 256; ++a)
            {
                for (int b = 0; b < 256; ++b)
                {
                    int r = GF.Mul(a, b);
                    Assert.AreEqual(OracleMul(a, b), r, "mul(" + a + "," + b + ")");
                    Assert.IsTrue(r >= 0 && r < 256, "mul(" + a + "," + b + ") out of range: " + r);
                }
            }
        }

        [Test]
        public void SqrAgainstOracle()
        {
            for (int a = 0; a < 256; ++a)
            {
                int r = GF.Sqr(a);
                Assert.AreEqual(OracleMul(a, a), r, "sqr(" + a + ")");
                Assert.IsTrue(r >= 0 && r < 256, "sqr(" + a + ") out of range: " + r);
            }
        }

        [Test]
        public void InvAgainstOracle()
        {
            Assert.AreEqual(0, GF.Inv(0), "inv(0)");

            for (int a = 0; a < 256; ++a)
            {
                int r = GF.Inv(a);
                Assert.AreEqual(OracleInv(a), r, "inv(" + a + ")");
                Assert.IsTrue(r >= 0 && r < 256, "inv(" + a + ") out of range: " + r);
            }
        }

        [Test]
        public void DivAgainstOracle()
        {
            for (int a = 0; a < 256; ++a)
            {
                for (int b = 0; b < 256; ++b)
                {
                    Assert.AreEqual(OracleMul(a, OracleInv(b)), GF.Div(a, b), "div(" + a + "," + b + ")");
                }
            }
        }

        /**
         * Mul3 is exercised on a stride rather than all 16777216 triples; Mul itself is covered exhaustively above
         * and Mul3 is defined in terms of it.
         */
        [Test]
        public void Mul3AgainstOracle()
        {
            for (int a = 0; a < 256; a += 5)
            {
                for (int b = 0; b < 256; b += 5)
                {
                    for (int c = 0; c < 256; c += 5)
                    {
                        int expected = OracleMul(OracleMul(a, b), c);
                        Assert.AreEqual(expected, GF.Mul3(a, b, c), "mul3(" + a + "," + b + "," + c + ")");
                    }
                }
            }

            // the zero cases matter: the table implementation masked them explicitly
            for (int a = 0; a < 256; ++a)
            {
                Assert.AreEqual(0, GF.Mul3(0, a, 1), "mul3(0," + a + ",1)");
                Assert.AreEqual(0, GF.Mul3(a, 0, 1), "mul3(" + a + ",0,1)");
                Assert.AreEqual(0, GF.Mul3(a, 1, 0), "mul3(" + a + ",1,0)");
            }
        }

        [Test]
        public void FieldLaws()
        {
            for (int a = 0; a < 256; ++a)
            {
                Assert.AreEqual(0, GF.Mul(a, 0), "mul(" + a + ",0)");
                Assert.AreEqual(0, GF.Mul(0, a), "mul(0," + a + ")");
                Assert.AreEqual(a, GF.Mul(a, 1), "mul(" + a + ",1)");
                Assert.AreEqual(a, GF.Mul(1, a), "mul(1," + a + ")");

                if (a != 0)
                {
                    Assert.AreEqual(1, GF.Mul(a, GF.Inv(a)), "a * inv(a) for a=" + a);
                    Assert.AreEqual(a, GF.Inv(GF.Inv(a)), "inv(inv(a)) for a=" + a);
                    Assert.AreEqual(1, GF.Div(a, a), "div(a,a) for a=" + a);
                }

                for (int b = 0; b < 256; ++b)
                {
                    Assert.AreEqual(GF.Mul(a, b), GF.Mul(b, a), "commutativity " + a + "," + b);

                    if (b != 0)
                    {
                        Assert.AreEqual(a, GF.Div(GF.Mul(a, b), b), "div(mul(a,b),b) for a=" + a + " b=" + b);
                    }
                }
            }

            // distributivity over the additive group (XOR), on a stride
            for (int a = 0; a < 256; a += 3)
            {
                for (int b = 0; b < 256; b += 3)
                {
                    for (int c = 0; c < 256; c += 7)
                    {
                        Assert.AreEqual(GF.Mul(a, b) ^ GF.Mul(a, c), GF.Mul(a, b ^ c),
                            "distributivity " + a + "," + b + "," + c);
                    }
                }
            }
        }
    }
}
