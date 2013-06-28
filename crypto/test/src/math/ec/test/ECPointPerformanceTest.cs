using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Math.EC.Tests
{
	/**
	* Compares the performance of the the window NAF point multiplication against
	* conventional point multiplication.
	*/
	[TestFixture, Explicit]
	public class ECPointPerformanceTest
	{
		public const int NUM_ROUNDS = 100;

		private void randMult(string curveName)
		{
			X9ECParameters spec = SecNamedCurves.GetByName(curveName);

			BigInteger n = spec.N;
			ECPoint g = (ECPoint) spec.G;
			SecureRandom random = new SecureRandom(); //SecureRandom.getInstance("SHA1PRNG", "SUN");
			BigInteger k = new BigInteger(n.BitLength - 1, random);

			ECPoint qMultiply = null;
			long startTime = DateTimeUtilities.CurrentUnixMs();
			for (int i = 0; i < NUM_ROUNDS; i++)
			{
				qMultiply = g.Multiply(k);
			}
			long endTime = DateTimeUtilities.CurrentUnixMs();

			double avgDuration = (double) (endTime - startTime) / NUM_ROUNDS;
			Console.WriteLine(curveName);
			Console.Write("Millis   : ");
			Console.WriteLine(avgDuration);
			Console.WriteLine();
		}

		[Test]
		public void TestMultiply()
		{
			randMult("sect163k1");
			randMult("sect163r2");
			randMult("sect233k1");
			randMult("sect233r1");
			randMult("sect283k1");
			randMult("sect283r1");
			randMult("sect409k1");
			randMult("sect409r1");
			randMult("sect571k1");
			randMult("sect571r1");
			randMult("secp224k1");
			randMult("secp224r1");
			randMult("secp256k1");
			randMult("secp256r1");
			randMult("secp521r1");
		}

		// public static void Main(string argv[])
		// {
		// ECMultiplyPerformanceTest test = new ECMultiplyPerformanceTest();
		// Test.testMultiply();
		// }
	}
}
