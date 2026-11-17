using System;

using NUnit.Framework;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Utilities.Test
{
    [TestFixture]
    public class BigIntegersTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        // q of the RFC 6509 SAKKE parameter set: 1022 bits, so its top word has slack
        private static readonly BigInteger SakkeQ = new BigInteger(
            "265EAEC7C2958FF69971846636B4195E905B0338672D20986FA6B8D62CF8068B" +
            "BD02AAC9F8BF03C6C8A1CC354C69672C39E46CE7FDF222864D5B49FD2999A9B4" +
            "389B1921CC9AD335144AB173595A07386DABFD2A0C614AA0A9F3CF14870F026A" +
            "A7E535ABD5A5C7C7FF38FA08E2615F6C203177C42B1EB3A1D99B601EBFAA17FB", 16);

        // SM9's N and P-256's order are exactly 256 bits, so sums carry out of, and borrows show in, the top word
        private static readonly BigInteger Sm9N =
            new BigInteger("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D", 16);
        private static readonly BigInteger P256N =
            new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

        private static BigInteger[] AddSubtractModuli() => new BigInteger[]
        {
            SakkeQ, Sm9N, P256N, BigInteger.One, BigInteger.Three, BigInteger.Four, BigInteger.One.ShiftLeft(32),
            BigInteger.One.ShiftLeft(32).Subtract(BigInteger.One), BigInteger.One.ShiftLeft(31).Add(BigInteger.One),
            // either side of the stackalloc bound
            BigInteger.One.ShiftLeft(2047).Add(BigInteger.One), BigInteger.One.ShiftLeft(2048).Add(BigInteger.One),
        };

        private static BigInteger[] MultModuli() => new BigInteger[]
        {
            Sm9N, P256N, SakkeQ, BigInteger.One, BigInteger.Three, BigInteger.Five, BigInteger.ValueOf(0xFFFFFFFFL),
            BigInteger.One.ShiftLeft(32).Add(BigInteger.One), BigInteger.One.ShiftLeft(64).Subtract(BigInteger.One),
            BigInteger.One.ShiftLeft(127).Subtract(BigInteger.One),
            // either side of the stackalloc bound
            BigInteger.One.ShiftLeft(2048).Subtract(BigInteger.One), BigInteger.One.ShiftLeft(2048).Add(BigInteger.One),
        };

        [Test]
        public void ModAdd()
        {
            foreach (BigInteger m in AddSubtractModuli())
            {
                BigInteger last = m.Subtract(BigInteger.One);

                CheckModAdd(m, BigInteger.Zero, BigInteger.Zero);
                CheckModAdd(m, BigInteger.Zero, last);
                CheckModAdd(m, last, BigInteger.Zero);
                CheckModAdd(m, last, last);
                CheckModAdd(m, last.ShiftRight(1), last);

                if (m.CompareTo(BigInteger.Two) > 0)
                {
                    // the sum is exactly m, the one case the conditional subtraction has to take
                    CheckModAdd(m, BigInteger.One, last);
                    CheckModAdd(m, last, BigInteger.One);
                }

                for (int j = 0; j < 200; ++j)
                {
                    CheckModAdd(m, RandomBelow(m), RandomBelow(m));
                }
            }

            CheckOperandErrors(BigIntegers.ModAdd, SakkeQ);
        }

        [Test]
        public void ModSubtract()
        {
            foreach (BigInteger m in AddSubtractModuli())
            {
                BigInteger last = m.Subtract(BigInteger.One);

                // zero minus last is the deepest underflow the range allows
                CheckModSubtract(m, BigInteger.Zero, BigInteger.Zero);
                CheckModSubtract(m, BigInteger.Zero, last);
                CheckModSubtract(m, last, BigInteger.Zero);
                CheckModSubtract(m, last, last);
                CheckModSubtract(m, last.ShiftRight(1), last);

                if (m.CompareTo(BigInteger.Two) > 0)
                {
                    // either side of the boundary: one short of underflowing, and one past it
                    CheckModSubtract(m, BigInteger.One, BigInteger.One);
                    CheckModSubtract(m, BigInteger.Zero, BigInteger.One);
                    CheckModSubtract(m, BigInteger.One, last);
                    CheckModSubtract(m, last, BigInteger.One);
                }

                for (int j = 0; j < 200; ++j)
                {
                    CheckModSubtract(m, RandomBelow(m), RandomBelow(m));
                }
            }

            CheckOperandErrors(BigIntegers.ModSubtract, SakkeQ);
        }

        [Test]
        public void ModMult()
        {
            foreach (BigInteger m in MultModuli())
            {
                BigInteger last = m.Subtract(BigInteger.One);

                CheckModMult(m, BigInteger.Zero, BigInteger.Zero);
                CheckModMult(m, BigInteger.Zero, last);
                CheckModMult(m, last, BigInteger.Zero);
                CheckModMult(m, last, last);

                if (m.CompareTo(BigInteger.One) > 0)
                {
                    CheckModMult(m, BigInteger.One, last);
                    CheckModMult(m, last, BigInteger.One);
                    CheckModMult(m, last.ShiftRight(1), last.ShiftRight(1));
                }

                for (int j = 0; j < 200; ++j)
                {
                    BigInteger x = RandomBelow(m);
                    BigInteger y = RandomBelow(m);

                    CheckModMult(m, x, y);

                    // x * x^-1 is 1, which pins the Montgomery factor rather than just the product; some of the
                    // moduli are composite, so only for units
                    if (x.SignValue != 0 && m.CompareTo(BigInteger.One) > 0 && x.Gcd(m).Equals(BigInteger.One))
                    {
                        Assert.AreEqual(BigInteger.One, BigIntegers.ModMult(m, x, BigIntegers.ModOddInverse(m, x)),
                            "m=" + m.ToString(16) + " x=" + x.ToString(16));
                    }
                }
            }

            CheckOperandErrors(BigIntegers.ModMult, P256N);

            // Montgomery form needs R coprime to the modulus, so an even one has no representation
            Assert.Throws<ArgumentException>(
                () => BigIntegers.ModMult(BigInteger.Four, BigInteger.One, BigInteger.One));
        }

        [Test]
        public void ModPowBaseBlinded()
        {
            // prime moduli, down to the smallest with room for a blinding value in [2, M - 2]
            BigInteger[] moduli = { SakkeQ, Sm9N, P256N, BigInteger.ValueOf(5), BigInteger.ValueOf(7) };

            foreach (BigInteger m in moduli)
            {
                BigInteger mSub1 = m.Subtract(BigInteger.One);
                BigInteger[] bases = { BigInteger.One, mSub1, RandomBelow(mSub1).Add(BigInteger.One),
                    RandomBelow(mSub1).Add(BigInteger.One) };
                BigInteger[] exponents = { BigInteger.Zero, BigInteger.One, mSub1, RandomBelow(m), RandomBelow(m),
                    new BigInteger(m.BitLength + 64, Random) };

                foreach (BigInteger x in bases)
                {
                    foreach (BigInteger e in exponents)
                    {
                        // the blinding value differs on each call and must cancel exactly
                        Assert.AreEqual(x.ModPow(e, m), BigIntegers.ModPowBaseBlinded(m, x, e, Random));
                    }
                }
            }

            // the base must be in [1, M)
            foreach (BigInteger x in new BigInteger[]{ BigInteger.Zero, BigInteger.One.Negate(), P256N })
            {
                Assert.Throws<ArgumentException>(
                    () => BigIntegers.ModPowBaseBlinded(P256N, x, BigInteger.Two, Random));
            }
        }

        private static void CheckModAdd(BigInteger m, BigInteger x, BigInteger y) =>
            CheckResult(m, x, y, x.Add(y).Mod(m), BigIntegers.ModAdd(m, x, y));

        private static void CheckModMult(BigInteger m, BigInteger x, BigInteger y) =>
            CheckResult(m, x, y, x.Multiply(y).Mod(m), BigIntegers.ModMult(m, x, y));

        private static void CheckModSubtract(BigInteger m, BigInteger x, BigInteger y) =>
            CheckResult(m, x, y, x.Subtract(y).Mod(m), BigIntegers.ModSubtract(m, x, y));

        private static void CheckResult(BigInteger m, BigInteger x, BigInteger y, BigInteger expected, BigInteger z)
        {
            Assert.AreEqual(expected, z, "m=" + m.ToString(16) + " x=" + x.ToString(16) + " y=" + y.ToString(16));
            Assert.IsTrue(z.SignValue >= 0 && z.CompareTo(m) < 0, "not reduced: " + z.ToString(16));
        }

        // an operand outside [0, M) is rejected rather than reduced: reducing it is the variable-time step these
        // methods exist to avoid
        private static void CheckOperandErrors(Func<BigInteger, BigInteger, BigInteger, BigInteger> op, BigInteger m)
        {
            BigInteger one = BigInteger.One, minusOne = one.Negate();

            Assert.Throws<ArgumentException>(() => op(m, m, one));
            Assert.Throws<ArgumentException>(() => op(m, one, m));
            Assert.Throws<ArgumentException>(() => op(m, minusOne, one));
            Assert.Throws<ArgumentException>(() => op(m, one, minusOne));

            BigInteger notPositive = m.Negate();
            Assert.Throws<ArithmeticException>(() => op(notPositive, BigInteger.Zero, BigInteger.Zero));
        }

        private static BigInteger RandomBelow(BigInteger m) => new BigInteger(m.BitLength + 8, Random).Mod(m);
    }
}
