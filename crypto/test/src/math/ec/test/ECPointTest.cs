using System;
using System.Collections;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Math.EC.Tests
{
    /**
     * Test class for {@link org.bouncycastle.math.ec.ECPoint ECPoint}. All
     * literature values are taken from "Guide to elliptic curve cryptography",
     * Darrel Hankerson, Alfred J. Menezes, Scott Vanstone, 2004, Springer-Verlag
     * New York, Inc.
     */
    [TestFixture]
    public class ECPointTest
    {
        /**
         * Random source used to generate random points
         */
        private SecureRandom Random = new SecureRandom();

        /**
         * Nested class containing sample literature values for <code>Fp</code>.
         */
        public class Fp
        {
            internal static readonly BigInteger q = new BigInteger("29");

            internal static readonly BigInteger a = new BigInteger("4");

            internal static readonly BigInteger b = new BigInteger("20");

            internal static readonly BigInteger n = new BigInteger("38");

            internal static readonly BigInteger h = new BigInteger("1");

            internal static readonly ECCurve curve = new FpCurve(q, a, b, n, h);

            internal static readonly ECPoint infinity = curve.Infinity;

            internal static readonly int[] pointSource = { 5, 22, 16, 27, 13, 6, 14, 6 };

            internal static ECPoint[] p = new ECPoint[pointSource.Length / 2];

            /**
             * Creates the points on the curve with literature values.
             */
            internal static void CreatePoints()
            {
                for (int i = 0; i < pointSource.Length / 2; i++)
                {
                    p[i] = curve.CreatePoint(
                        new BigInteger(pointSource[2 * i].ToString()),
                        new BigInteger(pointSource[2 * i + 1].ToString()));
                }
            }
        }

        /**
         * Nested class containing sample literature values for <code>F2m</code>.
         */
        public class F2m
        {
            // Irreducible polynomial for TPB z^4 + z + 1
            internal const int m = 4;

            internal const int k1 = 1;

            // a = z^3
            internal static readonly BigInteger aTpb = new BigInteger("1000", 2);

            // b = z^3 + 1
            internal static readonly BigInteger bTpb = new BigInteger("1001", 2);

            internal static readonly BigInteger n = new BigInteger("23");

            internal static readonly BigInteger h = new BigInteger("1");

            internal static readonly ECCurve curve = new F2mCurve(m, k1, aTpb, bTpb, n, h);

            internal static readonly ECPoint infinity = curve.Infinity;

            internal static readonly String[] pointSource = { "0010", "1111", "1100", "1100",
                    "0001", "0001", "1011", "0010" };

            internal static readonly ECPoint[] p = new ECPoint[pointSource.Length / 2];

            /**
             * Creates the points on the curve with literature values.
             */
            internal static void CreatePoints()
            {
                for (int i = 0; i < pointSource.Length / 2; i++)
                {
                    p[i] = curve.CreatePoint(
                        new BigInteger(pointSource[2 * i], 2),
                        new BigInteger(pointSource[2 * i + 1], 2));
                }
            }
        }

        [SetUp]
        public void SetUp()
        {
            Fp.CreatePoints();
            F2m.CreatePoints();
        }

        /**
         * Tests, if inconsistent points can be created, i.e. points with exactly
         * one null coordinate (not permitted).
         */
        [Test]
        public void TestPointCreationConsistency()
        {
            try
            {
                ECPoint bad = Fp.curve.CreatePoint(BigInteger.ValueOf(12), null);
                Assert.Fail();
            }
            catch (ArgumentException)
            {
                // Expected
            }

            try
            {
                ECPoint bad = Fp.curve.CreatePoint(null, BigInteger.ValueOf(12));
                Assert.Fail();
            }
            catch (ArgumentException)
            {
                // Expected
            }

            try
            {
                ECPoint bad = F2m.curve.CreatePoint(new BigInteger("1011"), null);
                Assert.Fail();
            }
            catch (ArgumentException)
            {
                // Expected
            }

            try
            {
                ECPoint bad = F2m.curve.CreatePoint(null, new BigInteger("1011"));
                Assert.Fail();
            }
            catch (ArgumentException)
            {
                // Expected
            }
        }

        /**
         * Tests <code>ECPoint.add()</code> against literature values.
         *
         * @param p
         *            The array of literature values.
         * @param infinity
         *            The point at infinity on the respective curve.
         */
        private void ImplTestAdd(ECPoint[] p, ECPoint infinity)
        {
            AssertPointsEqual("p0 plus p1 does not equal p2", p[2], p[0].Add(p[1]));
            AssertPointsEqual("p1 plus p0 does not equal p2", p[2], p[1].Add(p[0]));
            for (int i = 0; i < p.Length; i++)
            {
                AssertPointsEqual("Adding infinity failed", p[i], p[i].Add(infinity));
                AssertPointsEqual("Adding to infinity failed", p[i], infinity.Add(p[i]));
            }
        }

        /**
         * Calls <code>implTestAdd()</code> for <code>Fp</code> and
         * <code>F2m</code>.
         */
        [Test]
        public void TestAdd()
        {
            ImplTestAdd(Fp.p, Fp.infinity);
            ImplTestAdd(F2m.p, F2m.infinity);
        }

        /**
         * Tests <code>ECPoint.twice()</code> against literature values.
         *
         * @param p
         *            The array of literature values.
         */
        private void ImplTestTwice(ECPoint[] p)
        {
            AssertPointsEqual("Twice incorrect", p[3], p[0].Twice());
            AssertPointsEqual("Add same point incorrect", p[3], p[0].Add(p[0]));
        }

        /**
         * Calls <code>implTestTwice()</code> for <code>Fp</code> and
         * <code>F2m</code>.
         */
        [Test]
        public void TestTwice()
        {
            ImplTestTwice(Fp.p);
            ImplTestTwice(F2m.p);
        }

        private void ImplTestThreeTimes(ECPoint[] p)
        {
            ECPoint P = p[0];
            ECPoint _3P = P.Add(P).Add(P);
            AssertPointsEqual("ThreeTimes incorrect", _3P, P.ThreeTimes());
            AssertPointsEqual("TwicePlus incorrect", _3P, P.TwicePlus(P));
        }

        /**
         * Calls <code>implTestThreeTimes()</code> for <code>Fp</code> and
         * <code>F2m</code>.
         */
        [Test]
        public void TestThreeTimes()
        {
            ImplTestThreeTimes(Fp.p);
            ImplTestThreeTimes(F2m.p);
        }

        /**
         * Goes through all points on an elliptic curve and checks, if adding a
         * point <code>k</code>-times is the same as multiplying the point by
         * <code>k</code>, for all <code>k</code>. Should be called for points
         * on very small elliptic curves only.
         *
         * @param p
         *            The base point on the elliptic curve.
         * @param infinity
         *            The point at infinity on the elliptic curve.
         */
        private void ImplTestAllPoints(ECPoint p, ECPoint infinity)
        {
            ECPoint adder = infinity;
            ECPoint multiplier = infinity;

            BigInteger i = BigInteger.One;
            do
            {
                adder = adder.Add(p);
                multiplier = p.Multiply(i);
                AssertPointsEqual("Results of Add() and Multiply() are inconsistent " + i, adder, multiplier);
                i = i.Add(BigInteger.One);
            }
            while (!(adder.Equals(infinity)));
        }

        /**
         * Calls <code>implTestAllPoints()</code> for the small literature curves,
         * both for <code>Fp</code> and <code>F2m</code>.
         */
        [Test]
        public void TestAllPoints()
        {
            for (int i = 0; i < Fp.p.Length; i++)
            {
                ImplTestAllPoints(Fp.p[i], Fp.infinity);
            }

            for (int i = 0; i < F2m.p.Length; i++)
            {
                ImplTestAllPoints(F2m.p[i], F2m.infinity);
            }
        }

        /**
         * Checks, if the point multiplication algorithm of the given point yields
         * the same result as point multiplication done by the reference
         * implementation given in <code>multiply()</code>. This method chooses a
         * random number by which the given point <code>p</code> is multiplied.
         *
         * @param p
         *            The point to be multiplied.
         * @param numBits
         *            The bitlength of the random number by which <code>p</code>
         *            is multiplied.
         */
        private void ImplTestMultiply(ECPoint p, int numBits)
        {
            BigInteger k = new BigInteger(numBits, Random);
            ECPoint reff = ECAlgorithms.ReferenceMultiply(p, k);
            ECPoint q = p.Multiply(k);
            AssertPointsEqual("ECPoint.Multiply is incorrect", reff, q);
        }

        /**
         * Checks, if the point multiplication algorithm of the given point yields
         * the same result as point multiplication done by the reference
         * implementation given in <code>multiply()</code>. This method tests
         * multiplication of <code>p</code> by every number of bitlength
         * <code>numBits</code> or less.
         *
         * @param p
         *            The point to be multiplied.
         * @param numBits
         *            Try every multiplier up to this bitlength
         */
        private void ImplTestMultiplyAll(ECPoint p, int numBits)
        {
            BigInteger bound = BigInteger.One.ShiftLeft(numBits);
            BigInteger k = BigInteger.Zero;

            do
            {
                ECPoint reff = ECAlgorithms.ReferenceMultiply(p, k);
                ECPoint q = p.Multiply(k);
                AssertPointsEqual("ECPoint.Multiply is incorrect", reff, q);
                k = k.Add(BigInteger.One);
            }
            while (k.CompareTo(bound) < 0);
        }

        /**
         * Tests <code>ECPoint.add()</code> and <code>ECPoint.subtract()</code>
         * for the given point and the given point at infinity.
         *
         * @param p
         *            The point on which the tests are performed.
         * @param infinity
         *            The point at infinity on the same curve as <code>p</code>.
         */
        private void ImplTestAddSubtract(ECPoint p, ECPoint infinity)
        {
            AssertPointsEqual("Twice and Add inconsistent", p.Twice(), p.Add(p));
            AssertPointsEqual("Twice p - p is not p", p, p.Twice().Subtract(p));
            AssertPointsEqual("TwicePlus(p, -p) is not p", p, p.TwicePlus(p.Negate()));
            AssertPointsEqual("p - p is not infinity", infinity, p.Subtract(p));
            AssertPointsEqual("p plus infinity is not p", p, p.Add(infinity));
            AssertPointsEqual("infinity plus p is not p", p, infinity.Add(p));
            AssertPointsEqual("infinity plus infinity is not infinity ", infinity, infinity.Add(infinity));
            AssertPointsEqual("Twice infinity is not infinity ", infinity, infinity.Twice());
        }

        /**
         * Calls <code>implTestAddSubtract()</code> for literature values, both
         * for <code>Fp</code> and <code>F2m</code>.
         */
        [Test]
        public void TestAddSubtractMultiplySimple()
        {
            int fpBits = Fp.curve.Order.BitLength;
            for (int iFp = 0; iFp < Fp.pointSource.Length / 2; iFp++)
            {
                ImplTestAddSubtract(Fp.p[iFp], Fp.infinity);

                ImplTestMultiplyAll(Fp.p[iFp], fpBits);
                ImplTestMultiplyAll(Fp.infinity, fpBits);
            }

            int f2mBits = F2m.curve.Order.BitLength;
            for (int iF2m = 0; iF2m < F2m.pointSource.Length / 2; iF2m++)
            {
                ImplTestAddSubtract(F2m.p[iF2m], F2m.infinity);

                ImplTestMultiplyAll(F2m.p[iF2m], f2mBits);
                ImplTestMultiplyAll(F2m.infinity, f2mBits);
            }
        }

        /**
         * Test encoding with and without point compression.
         *
         * @param p
         *            The point to be encoded and decoded.
         */
        private void ImplTestEncoding(ECPoint p)
        {
            // Not Point Compression
            byte[] unCompBarr = p.GetEncoded(false);
            ECPoint decUnComp = p.Curve.DecodePoint(unCompBarr);
            AssertPointsEqual("Error decoding uncompressed point", p, decUnComp);

            // Point compression
            byte[] compBarr = p.GetEncoded(true);
            ECPoint decComp = p.Curve.DecodePoint(compBarr);
            AssertPointsEqual("Error decoding compressed point", p, decComp);
        }

        private void ImplAddSubtractMultiplyTwiceEncodingTest(ECCurve curve, ECPoint q, BigInteger n)
        {
            // Get point at infinity on the curve
            ECPoint infinity = curve.Infinity;

            ImplTestAddSubtract(q, infinity);
            ImplTestMultiply(q, n.BitLength);
            ImplTestMultiply(infinity, n.BitLength);

            int logSize = 32 - Integers.NumberOfLeadingZeros(curve.FieldSize - 1);
            int rounds = System.Math.Max(2, System.Math.Min(10, 32 - 3 * logSize));

            ECPoint p = q;
            for (int i = 0; ; )
            {
                ImplTestEncoding(p);
                if (++i == rounds)
                    break;
                p = p.Twice();
            }
        }

        private void ImplSqrtTest(ECCurve c)
        {
            if (ECAlgorithms.IsFpCurve(c))
            {
                BigInteger p = c.Field.Characteristic;
                BigInteger pMinusOne = p.Subtract(BigInteger.One);
                BigInteger legendreExponent = p.ShiftRight(1);

                int count = 0;
                while (count < 10)
                {
                    BigInteger nonSquare = BigIntegers.CreateRandomInRange(BigInteger.Two, pMinusOne, Random);
                    if (!nonSquare.ModPow(legendreExponent, p).Equals(BigInteger.One))
                    {
                        ECFieldElement root = c.FromBigInteger(nonSquare).Sqrt();
                        Assert.IsNull(root);
                        ++count;
                    }
                }
            }
            else if (ECAlgorithms.IsF2mCurve(c))
            {
                int m = c.FieldSize;
                BigInteger x = new BigInteger(m, Random);
                ECFieldElement fe = c.FromBigInteger(x);
                for (int i = 0; i < 100; ++i)
                {
                    ECFieldElement sq = fe.Square();
                    ECFieldElement check = sq.Sqrt();
                    Assert.AreEqual(fe, check);
                    fe = sq;
                }
            }
        }

        private void ImplValidityTest(ECCurve c, ECPoint g)
        {
            Assert.IsTrue(g.IsValid());

            if (ECAlgorithms.IsF2mCurve(c))
            {
                BigInteger h = c.Cofactor;
                if (null != h)
                {
                    if (!h.TestBit(0))
                    {
                        ECFieldElement sqrtB = c.B.Sqrt();
                        ECPoint order2 = c.CreatePoint(BigInteger.Zero, sqrtB.ToBigInteger());
                        Assert.IsTrue(order2.Twice().IsInfinity);
                        Assert.IsFalse(order2.IsValid());
                        ECPoint bad2 = g.Add(order2);
                        Assert.IsFalse(bad2.IsValid());
                        ECPoint good2 = bad2.Add(order2);
                        Assert.IsTrue(good2.IsValid());

                        if (!h.TestBit(1))
                        {
                            ECFieldElement L = SolveQuadraticEquation(c, c.A);
                            Assert.IsNotNull(L);
                            ECFieldElement T = sqrtB;
                            ECFieldElement x = T.Sqrt();
                            ECFieldElement y = T.Add(x.Multiply(L));
                            ECPoint order4 = c.CreatePoint(x.ToBigInteger(), y.ToBigInteger());
                            Assert.IsTrue(order4.Twice().Equals(order2));
                            Assert.IsFalse(order4.IsValid());
                            ECPoint bad4_1 = g.Add(order4);
                            Assert.IsFalse(bad4_1.IsValid());
                            ECPoint bad4_2 = bad4_1.Add(order4);
                            Assert.IsFalse(bad4_2.IsValid());
                            ECPoint bad4_3 = bad4_2.Add(order4);
                            Assert.IsFalse(bad4_3.IsValid());
                            ECPoint good4 = bad4_3.Add(order4);
                            Assert.IsTrue(good4.IsValid());
                        }
                    }
                }
            }
        }

        private void ImplAddSubtractMultiplyTwiceEncodingTestAllCoords(X9ECParameters x9ECParameters)
        {
            BigInteger n = x9ECParameters.N;
            ECPoint G = x9ECParameters.G;
            ECCurve C = x9ECParameters.Curve;

            int[] coords = ECCurve.GetAllCoordinateSystems();
            for (int i = 0; i < coords.Length; ++i)
            {
                int coord = coords[i];
                if (C.SupportsCoordinateSystem(coord))
                {
                    ECCurve c = C;
                    ECPoint g = G;

                    if (c.CoordinateSystem != coord)
                    {
                        c = C.Configure().SetCoordinateSystem(coord).Create();
                        g = c.ImportPoint(G);
                    }

                    // The generator is multiplied by random b to get random q
                    BigInteger b = new BigInteger(n.BitLength, Random);
                    ECPoint q = g.Multiply(b).Normalize();

                    ImplAddSubtractMultiplyTwiceEncodingTest(c, q, n);

                    ImplSqrtTest(c);

                    ImplValidityTest(c, g);
                }
            }
        }

        /**
         * Calls <code>implTestAddSubtract()</code>,
         * <code>implTestMultiply</code> and <code>implTestEncoding</code> for
         * the standard elliptic curves as given in <code>SecNamedCurves</code>.
         */
        [Test]
        public void TestAddSubtractMultiplyTwiceEncoding()
        {
            ArrayList names = new ArrayList();
            CollectionUtilities.AddRange(names, ECNamedCurveTable.Names);
            CollectionUtilities.AddRange(names, CustomNamedCurves.Names);

            ISet uniqNames = new HashSet(names);

            foreach (string name in uniqNames)
            {
                X9ECParameters x9A = ECNamedCurveTable.GetByName(name);
                X9ECParameters x9B = CustomNamedCurves.GetByName(name);

                if (x9A != null && x9B != null)
                {
                    Assert.AreEqual(x9A.Curve.Field, x9B.Curve.Field);
                    Assert.AreEqual(x9A.Curve.A.ToBigInteger(), x9B.Curve.A.ToBigInteger());
                    Assert.AreEqual(x9A.Curve.B.ToBigInteger(), x9B.Curve.B.ToBigInteger());
                    AssertOptionalValuesAgree(x9A.Curve.Cofactor, x9B.Curve.Cofactor);
                    AssertOptionalValuesAgree(x9A.Curve.Order, x9B.Curve.Order);

                    AssertPointsEqual("Custom curve base-point inconsistency", x9A.G, x9B.G);

                    Assert.AreEqual(x9A.H, x9B.H);
                    Assert.AreEqual(x9A.N, x9B.N);
                    AssertOptionalValuesAgree(x9A.GetSeed(), x9B.GetSeed());

                    BigInteger k = new BigInteger(x9A.N.BitLength, Random);
                    ECPoint pA = x9A.G.Multiply(k);
                    ECPoint pB = x9B.G.Multiply(k);
                    AssertPointsEqual("Custom curve multiplication inconsistency", pA, pB);
                }

                if (x9A != null)
                {
                    ImplAddSubtractMultiplyTwiceEncodingTestAllCoords(x9A);
                }

                if (x9B != null)
                {
                    ImplAddSubtractMultiplyTwiceEncodingTestAllCoords(x9B);
                }
            }
        }

        [Test]
        public void TestExampleFpB0()
        {
            /*
             * The supersingular curve y^2 = x^3 - 3.x (i.e. with 'B' == 0) from RFC 6508 2.1, with
             * curve parameters from RFC 6509 Appendix A.
             */
            BigInteger p = FromHex(
                  "997ABB1F0A563FDA65C61198DAD0657A"
                + "416C0CE19CB48261BE9AE358B3E01A2E"
                + "F40AAB27E2FC0F1B228730D531A59CB0"
                + "E791B39FF7C88A19356D27F4A666A6D0"
                + "E26C6487326B4CD4512AC5CD65681CE1"
                + "B6AFF4A831852A82A7CF3C521C3C09AA"
                + "9F94D6AF56971F1FFCE3E82389857DB0"
                + "80C5DF10AC7ACE87666D807AFEA85FEB");
            BigInteger a = p.Subtract(BigInteger.ValueOf(3));
            BigInteger b = BigInteger.Zero;
            byte[] S = null;
            BigInteger n = p.Add(BigInteger.One).ShiftRight(2);
            BigInteger h = BigInteger.ValueOf(4);

            ECCurve curve = ConfigureCurve(new FpCurve(p, a, b, n, h));

            X9ECPoint G = ConfigureBasepoint(curve, "04"
                // Px
                + "53FC09EE332C29AD0A7990053ED9B52A"
                + "2B1A2FD60AEC69C698B2F204B6FF7CBF"
                + "B5EDB6C0F6CE2308AB10DB9030B09E10"
                + "43D5F22CDB9DFA55718BD9E7406CE890"
                + "9760AF765DD5BCCB337C86548B72F2E1"
                + "A702C3397A60DE74A7C1514DBA66910D"
                + "D5CFB4CC80728D87EE9163A5B63F73EC"
                + "80EC46C4967E0979880DC8ABEAE63895"
                // Py
                + "0A8249063F6009F1F9F1F0533634A135"
                + "D3E82016029906963D778D821E141178"
                + "F5EA69F4654EC2B9E7F7F5E5F0DE55F6"
                + "6B598CCF9A140B2E416CFF0CA9E032B9"
                + "70DAE117AD547C6CCAD696B5B7652FE0"
                + "AC6F1E80164AA989492D979FC5A4D5F2"
                + "13515AD7E9CB99A980BDAD5AD5BB4636"
                + "ADB9B5706A67DCDE75573FD71BEF16D7");

            X9ECParameters x9 = new X9ECParameters(curve, G, n, h, S);

            ImplAddSubtractMultiplyTwiceEncodingTestAllCoords(x9);
        }

        private void AssertPointsEqual(string message, ECPoint a, ECPoint b)
        {
            // NOTE: We intentionally test points for equality in both directions
            Assert.AreEqual(a, b, message);
            Assert.AreEqual(b, a, message);
        }

        private void AssertOptionalValuesAgree(object a, object b)
        {
            if (a != null && b != null)
            {
                Assert.AreEqual(a, b);
            }
        }

        private void AssertOptionalValuesAgree(byte[] a, byte[] b)
        {
            if (a != null && b != null)
            {
                Assert.IsTrue(Arrays.AreEqual(a, b));
            }
        }

        private static X9ECPoint ConfigureBasepoint(ECCurve curve, string encoding)
        {
            X9ECPoint G = new X9ECPoint(curve, Hex.Decode(encoding));
            //WNafUtilities.ConfigureBasepoint(G.Point);
            return G;
        }

        private static ECCurve ConfigureCurve(ECCurve curve)
        {
            return curve;
        }

        private static BigInteger FromHex(string hex)
        {
            return new BigInteger(1, Hex.Decode(hex));
        }

        private static ECFieldElement SolveQuadraticEquation(ECCurve c, ECFieldElement rhs)
        {
            if (rhs.IsZero)
                return rhs;

            ECFieldElement gamma, z, zeroElement = c.FromBigInteger(BigInteger.Zero);

            int m = c.FieldSize;
            do
            {
                ECFieldElement t = c.FromBigInteger(BigInteger.Arbitrary(m));
                z = zeroElement;
                ECFieldElement w = rhs;
                for (int i = 1; i < m; i++)
                {
                    ECFieldElement w2 = w.Square();
                    z = z.Square().Add(w2.Multiply(t));
                    w = w2.Add(rhs);
                }
                if (!w.IsZero)
                {
                    return null;
                }
                gamma = z.Square().Add(z);
            }
            while (gamma.IsZero);

            return z;
        }
    }
}
