using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
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

			internal static FpPoint[] p = new FpPoint[pointSource.Length / 2];

			/**
			 * Creates the points on the curve with literature values.
			 */
			internal static void createPoints()
			{
				for (int i = 0; i < pointSource.Length / 2; i++)
				{
					FpFieldElement x = new FpFieldElement(q, new BigInteger(
						pointSource[2 * i].ToString()));
					FpFieldElement y = new FpFieldElement(q, new BigInteger(
						pointSource[2 * i + 1].ToString()));
					p[i] = new FpPoint(curve, x, y);
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
				FpPoint bad = new FpPoint(Fp.curve, new FpFieldElement(
					Fp.q, new BigInteger("12")), null);
				Assert.Fail();
			}
			catch (ArgumentException)
			{
				// Expected
			}

			try
			{
				FpPoint bad = new FpPoint(Fp.curve, null,
					new FpFieldElement(Fp.q, new BigInteger("12")));
				Assert.Fail();
			}
			catch (ArgumentException)
			{
				// Expected
			}

			try
			{
				F2mPoint bad = new F2mPoint(F2m.curve, new F2mFieldElement(
					F2m.m, F2m.k1, new BigInteger("1011")), null);
				Assert.Fail();
			}
			catch (ArgumentException)
			{
				// Expected
			}

			try
			{
				F2mPoint bad = new F2mPoint(F2m.curve, null,
					new F2mFieldElement(F2m.m, F2m.k1,
					new BigInteger("1011")));
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
		private void implTestAdd(ECPoint[] p, ECPoint infinity)
		{
			Assert.AreEqual(p[2], p[0].Add(p[1]), "p0 plus p1 does not equal p2");
			Assert.AreEqual(p[2], p[1].Add(p[0]), "p1 plus p0 does not equal p2");
			for (int i = 0; i < p.Length; i++)
			{
				Assert.AreEqual(p[i], p[i].Add(infinity), "Adding infinity failed");
				Assert.AreEqual(p[i], infinity.Add(p[i]), "Adding to infinity failed");
			}
		}

		/**
		 * Calls <code>implTestAdd()</code> for <code>Fp</code> and
		 * <code>F2m</code>.
		 */
		[Test]
		public void TestAdd()
		{
			implTestAdd(Fp.p, Fp.infinity);
			implTestAdd(F2m.p, F2m.infinity);
		}

		/**
		 * Tests <code>ECPoint.twice()</code> against literature values.
		 *
		 * @param p
		 *            The array of literature values.
		 */
		private void implTestTwice(ECPoint[] p)
		{
			Assert.AreEqual(p[3], p[0].Twice(), "Twice incorrect");
			Assert.AreEqual(p[3], p[0].Add(p[0]), "Add same point incorrect");
		}

		/**
		 * Calls <code>implTestTwice()</code> for <code>Fp</code> and
		 * <code>F2m</code>.
		 */
		[Test]
		public void TestTwice()
		{
			implTestTwice(Fp.p);
			implTestTwice(F2m.p);
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
		private void implTestAllPoints(ECPoint p, ECPoint infinity)
		{
			ECPoint adder = infinity;
			ECPoint multiplier = infinity;
			int i = 1;
			do
			{
				adder = adder.Add(p);
				multiplier = p.Multiply(new BigInteger(i.ToString()));
				Assert.AreEqual(adder, multiplier,
					"Results of add() and multiply() are inconsistent " + i);
				i++;
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
				implTestAllPoints(Fp.p[0], Fp.infinity);
			}

			for (int i = 0; i < F2m.p.Length; i++)
			{
				implTestAllPoints(F2m.p[0], F2m.infinity);
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
		private ECPoint multiply(ECPoint p, BigInteger k)
		{
			ECPoint q = p.Curve.Infinity;
			int t = k.BitLength;
			for (int i = 0; i < t; i++)
			{
				if (k.TestBit(i))
				{
					q = q.Add(p);
				}
				p = p.Twice();
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
		private void implTestMultiply(ECPoint p, int numBits)
		{
			BigInteger k = new BigInteger(numBits, secRand);
			ECPoint reff = multiply(p, k);
			ECPoint q = p.Multiply(k);
			Assert.AreEqual(reff, q, "ECPoint.multiply is incorrect");
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
		private void implTestMultiplyAll(ECPoint p, int numBits)
		{
			BigInteger bound = BigInteger.Two.Pow(numBits);
			BigInteger k = BigInteger.Zero;

			do
			{
				ECPoint reff = multiply(p, k);
				ECPoint q = p.Multiply(k);
				Assert.AreEqual(reff, q, "ECPoint.multiply is incorrect");
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
		private void implTestAddSubtract(ECPoint p, ECPoint infinity)
		{
			Assert.AreEqual(p.Twice(), p.Add(p), "Twice and Add inconsistent");
			Assert.AreEqual(p, p.Twice().Subtract(p), "Twice p - p is not p");
			Assert.AreEqual(infinity, p.Subtract(p), "p - p is not infinity");
			Assert.AreEqual(p, p.Add(infinity), "p plus infinity is not p");
			Assert.AreEqual(p, infinity.Add(p), "infinity plus p is not p");
			Assert.AreEqual(infinity, infinity.Add(infinity), "infinity plus infinity is not infinity ");
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
				implTestAddSubtract(Fp.p[iFp], Fp.infinity);

				// Could be any numBits, 6 is chosen at will
				implTestMultiplyAll(Fp.p[iFp], 6);
				implTestMultiplyAll(Fp.infinity, 6);
			}

			for (int iF2m = 0; iF2m < F2m.pointSource.Length / 2; iF2m++)
			{
				implTestAddSubtract(F2m.p[iF2m], F2m.infinity);

				// Could be any numBits, 6 is chosen at will
				implTestMultiplyAll(F2m.p[iF2m], 6);
				implTestMultiplyAll(F2m.infinity, 6);
			}
		}

		/**
		 * Test encoding with and without point compression.
		 *
		 * @param p
		 *            The point to be encoded and decoded.
		 */
		private void implTestEncoding(ECPoint p)
		{
			// Not Point Compression
			ECPoint unCompP;

			// Point compression
			ECPoint compP;

			if (p is FpPoint)
			{
				unCompP = new FpPoint(p.Curve, p.X, p.Y, false);
				compP = new FpPoint(p.Curve, p.X, p.Y, true);
			}
			else
			{
				unCompP = new F2mPoint(p.Curve, p.X, p.Y, false);
				compP = new F2mPoint(p.Curve, p.X, p.Y, true);
			}

			byte[] unCompBarr = unCompP.GetEncoded();
			ECPoint decUnComp = p.Curve.DecodePoint(unCompBarr);
			Assert.AreEqual(p, decUnComp, "Error decoding uncompressed point");

			byte[] compBarr = compP.GetEncoded();
			ECPoint decComp = p.Curve.DecodePoint(compBarr);
			Assert.AreEqual(p, decComp, "Error decoding compressed point");
		}

		/**
		 * Calls <code>implTestAddSubtract()</code>,
		 * <code>implTestMultiply</code> and <code>implTestEncoding</code> for
		 * the standard elliptic curves as given in <code>SecNamedCurves</code>.
		 */
		[Test]
		public void TestAddSubtractMultiplyTwiceEncoding()
		{
			foreach (string name in SecNamedCurves.Names)
			{
				X9ECParameters x9ECParameters = SecNamedCurves.GetByName(name);

				BigInteger n = x9ECParameters.N;

				// The generator is multiplied by random b to get random q
				BigInteger b = new BigInteger(n.BitLength, secRand);
				ECPoint g = x9ECParameters.G;
				ECPoint q = g.Multiply(b);

				// Get point at infinity on the curve
				ECPoint infinity = x9ECParameters.Curve.Infinity;

				implTestAddSubtract(q, infinity);
				implTestMultiply(q, n.BitLength);
				implTestMultiply(infinity, n.BitLength);
				implTestEncoding(q);
			}
		}
	}
}