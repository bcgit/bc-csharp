using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Prng;

namespace Org.BouncyCastle.Security.Tests
{
	[TestFixture]
	public class SecureRandomTest
	{
#if !NETCF_1_0
		[Test]
		public void TestCryptoApi()
		{
			SecureRandom random = new SecureRandom(
				new CryptoApiRandomGenerator());

			checkSecureRandom(random);
		}
#endif

		[Test]
		public void TestDefault()
		{
			SecureRandom random = new SecureRandom();

			checkSecureRandom(random);
		}

		[Test]
		public void TestSha1Prng()
		{
			SecureRandom random = SecureRandom.GetInstance("SHA1PRNG");
			random.SetSeed(SecureRandom.GetSeed(20));

			checkSecureRandom(random);
		}

		[Test]
		public void TestSha256Prng()
		{
			SecureRandom random = SecureRandom.GetInstance("SHA256PRNG");
			random.SetSeed(SecureRandom.GetSeed(32));

			checkSecureRandom(random);
		}

		[Test]
		public void TestThreadedSeed()
		{
			SecureRandom random = new SecureRandom(
				new ThreadedSeedGenerator().GenerateSeed(20, false));

			checkSecureRandom(random);
		}

		[Test]
		public void TestVmpcPrng()
		{
			SecureRandom random = new SecureRandom(new VmpcRandomGenerator());
			random.SetSeed(SecureRandom.GetSeed(32));

			checkSecureRandom(random);
		}


		private static void checkSecureRandom(
			SecureRandom random)
		{
			// Note: This will periodically (< 1e-6 probability) give a false alarm.
			// That's randomness for you!
			Assert.IsTrue(runChiSquaredTests(random), "Chi2 test detected possible non-randomness");
		}

		private static bool runChiSquaredTests(
			SecureRandom random)
		{
			int passes = 0;

			for (int tries = 0; tries < 100; ++tries)
			{
				double chi2 = measureChiSquared(random, 1000);
				if (chi2 < 285.0) // 255 degrees of freedom in test => Q ~ 10.0% for 285
					++passes;
			}

			return passes > 75;
		}

		private static double measureChiSquared(
			SecureRandom	random,
			int				rounds)
		{
			int[] counts = new int[256];

			byte[] bs = new byte[256];
			for (int i = 0; i < rounds; ++i)
			{
				random.NextBytes(bs);

				for (int b = 0; b < 256; ++b)
				{
					++counts[bs[b]];
				}
			}

			byte mask = SecureRandom.GetSeed(1)[0];
			for (int i = 0; i < rounds; ++i)
			{
				random.NextBytes(bs);

				for (int b = 0; b < 256; ++b)
				{
					++counts[bs[b] ^ mask];
				}

				++mask;
			}

			byte shift = SecureRandom.GetSeed(1)[0];
			for (int i = 0; i < rounds; ++i)
			{
				random.NextBytes(bs);

				for (int b = 0; b < 256; ++b)
				{
					++counts[(byte)(bs[b] + shift)];
				}

				++shift;
			}

			int total = 3 * rounds;

			double chi2 = 0;
			for (int k = 0; k < counts.Length; ++k)
			{
				double diff = ((double) counts[k]) - total;
				double diff2 = diff * diff;

				chi2 += diff2;
			}

			chi2 /= total;

			return chi2;
		}
	}
}
