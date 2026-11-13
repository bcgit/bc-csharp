using NUnit.Framework;

namespace Org.BouncyCastle.Math.Raw.Tests
{
    /// <summary>
    /// Exhaustive tests of <see cref="GF256Aes"/> against an independent oracle: log and exp tables built here by
    /// iterating the generator X + 1 over GF(2)[X]/(X^8 + X^4 + X^3 + X + 1). The oracle takes a different
    /// computational route (discrete logs) from the implementation (carryless multiply and reduce), and field laws are
    /// checked as well, in case both sides were to be wrong the same way.
    /// </summary>
    [TestFixture]
    public class GF256AesTest
    {
        private const int Modulus = 0x11B;
        private const int Order = 255;

        private static readonly int[] Exp = new int[Order];
        private static readonly int[] Log = new int[256];

        static GF256AesTest()
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

        /// <summary>
        /// Guard the oracle itself: these are the opening entries of the exp table for this field polynomial and
        /// generator, and the cycle must close back on 1.
        /// </summary>
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

        /// <summary>
        /// Published values: the FIPS 197 multiplication examples (Sections 4.2 and 4.2.1), and the inverse pair
        /// {53}, {CA}. Checked against both the oracle and the implementation.
        /// </summary>
        [Test]
        public void KnownValues()
        {
            Assert.AreEqual(0xC1, OracleMul(0x57, 0x83), "oracle {57}*{83}");
            Assert.AreEqual(0xC1, GF256Aes.Mul(0x57, 0x83), "{57}*{83}");
            Assert.AreEqual(0xFE, OracleMul(0x57, 0x13), "oracle {57}*{13}");
            Assert.AreEqual(0xFE, GF256Aes.Mul(0x57, 0x13), "{57}*{13}");
            Assert.AreEqual(0xCA, OracleInv(0x53), "oracle inv({53})");
            Assert.AreEqual(0xCA, GF256Aes.Inv(0x53), "inv({53})");
        }

        [Test]
        public void MulAgainstOracle()
        {
            for (int a = 0; a < 256; ++a)
            {
                for (int b = 0; b < 256; ++b)
                {
                    int r = GF256Aes.Mul(a, b);
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
                int r = GF256Aes.Sqr(a);
                Assert.AreEqual(OracleMul(a, a), r, "sqr(" + a + ")");
                Assert.IsTrue(r >= 0 && r < 256, "sqr(" + a + ") out of range: " + r);
            }
        }

        [Test]
        public void InvAgainstOracle()
        {
            for (int a = 0; a < 256; ++a)
            {
                int r = GF256Aes.Inv(a);
                Assert.AreEqual(OracleInv(a), r, "inv(" + a + ")");
                Assert.IsTrue(r >= 0 && r < 256, "inv(" + a + ") out of range: " + r);
            }
        }

        /// <summary>
        /// Only the low 8 bits of each argument are used, whatever the high bits (including the sign) hold.
        /// </summary>
        [Test]
        public void HighBitsIgnored()
        {
            int[] highs = { 0x100, 0x7FFFFF00, ~0xFF, int.MinValue };
            foreach (int h in highs)
            {
                for (int a = 0; a < 256; ++a)
                {
                    Assert.AreEqual(GF256Aes.Sqr(a), GF256Aes.Sqr(h | a), "sqr(" + h + "|" + a + ")");
                    Assert.AreEqual(GF256Aes.Inv(a), GF256Aes.Inv(h | a), "inv(" + h + "|" + a + ")");

                    for (int b = 0; b < 256; b += 7)
                    {
                        Assert.AreEqual(GF256Aes.Mul(a, b), GF256Aes.Mul(h | a, h | b),
                            "mul(" + h + "|" + a + "," + h + "|" + b + ")");
                    }
                }
            }
        }

        [Test]
        public void FieldLaws()
        {
            for (int a = 0; a < 256; ++a)
            {
                Assert.AreEqual(0, GF256Aes.Mul(a, 0), "mul(" + a + ",0)");
                Assert.AreEqual(0, GF256Aes.Mul(0, a), "mul(0," + a + ")");
                Assert.AreEqual(a, GF256Aes.Mul(a, 1), "mul(" + a + ",1)");
                Assert.AreEqual(a, GF256Aes.Mul(1, a), "mul(1," + a + ")");

                if (a != 0)
                {
                    Assert.AreEqual(1, GF256Aes.Mul(a, GF256Aes.Inv(a)), "a * inv(a) for a=" + a);
                    Assert.AreEqual(a, GF256Aes.Inv(GF256Aes.Inv(a)), "inv(inv(a)) for a=" + a);
                }

                for (int b = 0; b < 256; ++b)
                {
                    Assert.AreEqual(GF256Aes.Mul(a, b), GF256Aes.Mul(b, a), "commutativity " + a + "," + b);

                    if (b != 0)
                    {
                        Assert.AreEqual(a, GF256Aes.Mul(GF256Aes.Mul(a, b), GF256Aes.Inv(b)),
                            "mul(mul(a,b),inv(b)) for a=" + a + " b=" + b);
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
                        Assert.AreEqual(GF256Aes.Mul(a, b) ^ GF256Aes.Mul(a, c), GF256Aes.Mul(a, b ^ c),
                            "distributivity " + a + "," + b + "," + c);
                    }
                }
            }
        }
    }
}
