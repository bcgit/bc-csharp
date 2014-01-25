using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

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
        private SecureRandom secRand = new SecureRandom();

//		private ECPointTest.Fp fp = null;

//		private ECPointTest.F2m f2m = null;

        /**
         * Nested class containing sample literature values for <code>Fp</code>.
         */
        public class Fp
        {
            internal static readonly BigInteger q = new BigInteger("29");

            internal static readonly BigInteger a = new BigInteger("4");

            internal static readonly BigInteger b = new BigInteger("20");

            internal static readonly FpCurve curve = new FpCurve(q, a, b);

            internal static readonly FpPoint infinity = (FpPoint) curve.Infinity;

            internal static readonly int[] pointSource = { 5, 22, 16, 27, 13, 6, 14, 6 };

            internal static ECPoint[] p = new ECPoint[pointSource.Length / 2];

            /**
             * Creates the points on the curve with literature values.
             */
            internal static void createPoints()
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
            internal static readonly F2mFieldElement aTpb = new F2mFieldElement(m, k1,
                new BigInteger("8", 16));

            // b = z^3 + 1
            internal static readonly F2mFieldElement bTpb = new F2mFieldElement(m, k1,
                new BigInteger("9", 16));

            internal static readonly F2mCurve curve = new F2mCurve(m, k1, aTpb
                .ToBigInteger(), bTpb.ToBigInteger());

            internal static readonly F2mPoint infinity = (F2mPoint) curve.Infinity;

            internal static readonly string[] pointSource = { "2", "f", "c", "c", "1", "1", "b", "2" };

            internal static F2mPoint[] p = new F2mPoint[pointSource.Length / 2];

            /**
             * Creates the points on the curve with literature values.
             */
            internal static void createPoints()
            {
                for (int i = 0; i < pointSource.Length / 2; i++)
                {
                    F2mFieldElement x = new F2mFieldElement(m, k1,
                        new BigInteger(pointSource[2 * i], 16));
                    F2mFieldElement y = new F2mFieldElement(m, k1,
                        new BigInteger(pointSource[2 * i + 1], 16));
                    p[i] = new F2mPoint(curve, x, y);
                }
            }
        }

        [SetUp]
        public void setUp()
        {
//			fp = new ECPointTest.Fp();
            Fp.createPoints();

//			f2m = new ECPointTest.F2m();
            F2m.createPoints();
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
                ImplTestAllPoints(Fp.p[0], Fp.infinity);
            }

            for (int i = 0; i < F2m.p.Length; i++)
            {
                ImplTestAllPoints(F2m.p[0], F2m.infinity);
            }
        }

        /**
         * Simple shift-and-add multiplication. Serves as reference implementation
         * to verify (possibly faster) implementations in
         * {@link org.bouncycastle.math.ec.ECPoint ECPoint}.
         *
         * @param p
         *            The point to multiply.
         * @param k
         *            The multiplier.
         * @return The result of the point multiplication <code>kP</code>.
         */
        private ECPoint Multiply(ECPoint p, BigInteger k)
        {
            ECPoint q = p.Curve.Infinity;
            int t = k.BitLength;
            for (int i = 0; i < t; i++)
            {
                if (i != 0)
                {
                    p = p.Twice();
                }
                if (k.TestBit(i))
                {
                    q = q.Add(p);
                }
            }
            return q;
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
            BigInteger k = new BigInteger(numBits, secRand);
            ECPoint reff = Multiply(p, k);
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
                ECPoint reff = Multiply(p, k);
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
            for (int iFp = 0; iFp < Fp.pointSource.Length / 2; iFp++)
            {
                ImplTestAddSubtract(Fp.p[iFp], Fp.infinity);

                // Could be any numBits, 6 is chosen at will
                ImplTestMultiplyAll(Fp.p[iFp], 6);
                ImplTestMultiplyAll(Fp.infinity, 6);
            }

            for (int iF2m = 0; iF2m < F2m.pointSource.Length / 2; iF2m++)
            {
                ImplTestAddSubtract(F2m.p[iF2m], F2m.infinity);

                // Could be any numBits, 6 is chosen at will
                ImplTestMultiplyAll(F2m.p[iF2m], 6);
                ImplTestMultiplyAll(F2m.infinity, 6);
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
            ECPoint unCompP = p.Curve.CreatePoint(p.AffineXCoord.ToBigInteger(), p.AffineYCoord.ToBigInteger(), false);

            // Point compression
            ECPoint compP = p.Curve.CreatePoint(p.AffineXCoord.ToBigInteger(), p.AffineYCoord.ToBigInteger(), true);

            byte[] unCompBarr = unCompP.GetEncoded();
            ECPoint decUnComp = p.Curve.DecodePoint(unCompBarr);
            AssertPointsEqual("Error decoding uncompressed point", p, decUnComp);

            byte[] compBarr = compP.GetEncoded();
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
            ImplTestEncoding(q);
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
                    BigInteger b = new BigInteger(n.BitLength, secRand);
                    ECPoint q = g.Multiply(b).Normalize();

                    ImplAddSubtractMultiplyTwiceEncodingTest(c, q, n);
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
            foreach (string name in ECNamedCurveTable.Names)
            {
                X9ECParameters x9ECParameters = ECNamedCurveTable.GetByName(name);
                ImplAddSubtractMultiplyTwiceEncodingTestAllCoords(x9ECParameters);

                x9ECParameters = CustomNamedCurves.GetByName(name);
                if (x9ECParameters != null)
                {
                    ImplAddSubtractMultiplyTwiceEncodingTestAllCoords(x9ECParameters);
                }
            }
        }

        private void AssertPointsEqual(string message, ECPoint a, ECPoint b)
        {
            Assert.AreEqual(a, b, message);
        }
    }
}
