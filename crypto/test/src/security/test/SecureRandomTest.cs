using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security.Tests
{
    [TestFixture]
    [Parallelizable(ParallelScope.All)]
    public class SecureRandomTest
    {
        [Test]
        public void TestCryptoApi()
        {
            SecureRandom random = new SecureRandom(new CryptoApiRandomGenerator());

            CheckSecureRandom(random);
        }

        [Test]
        public void TestDefault()
        {
            SecureRandom random = new SecureRandom();

            CheckSecureRandom(random);
        }

        [Test]
        public void TestNextDouble()
        {
            double min = new SecureRandom(new FixedRandomGenerator(0x00)).NextDouble();
            Assert.GreaterOrEqual(min, 0.0);
            Assert.Less(min, 1.0);

            double max = new SecureRandom(new FixedRandomGenerator(0xFF)).NextDouble();
            Assert.GreaterOrEqual(max, 0.0);
            Assert.Less(max, 1.0);
        }

        [Test]
        public void TestSha1Prng()
        {
            SecureRandom random = SecureRandom.GetInstance("SHA1PRNG");

            CheckSecureRandom(random);
        }

        [Test]
        public void TestSha1PrngReplicable()
        {
            SecureRandom random = new SecureRandom();
            byte[] seed = SecureRandom.GetNextBytes(random, 16);

            SecureRandom sx = SecureRandom.GetInstance("SHA1PRNG", false); sx.SetSeed(seed);
            SecureRandom sy = SecureRandom.GetInstance("SHA1PRNG", false); sy.SetSeed(seed);

            byte[] bx = new byte[128]; sx.NextBytes(bx);
            byte[] by = new byte[128]; sy.NextBytes(by);

            Assert.IsTrue(Arrays.AreEqual(bx, by));
        }

        [Test]
        public void TestSha256Prng()
        {
            SecureRandom random = SecureRandom.GetInstance("SHA256PRNG");

            CheckSecureRandom(random);
        }

        [Test]
        public void TestSP800Ctr()
        {
            SecureRandom random = new SP800SecureRandomBuilder().BuildCtr(AesUtilities.CreateEngine(), 256, new byte[32], false);

            CheckSecureRandom(random);
        }

        [Test]
        public void TestSP800Hash()
        {
            SecureRandom random = new SP800SecureRandomBuilder().BuildHash(new Sha256Digest(), new byte[32], false);

            CheckSecureRandom(random);
        }

        [Test]
        public void TestSP800HMac()
        {
            SecureRandom random = new SP800SecureRandomBuilder().BuildHMac(new HMac(new Sha256Digest()), new byte[32], false);

            CheckSecureRandom(random);
        }

        [Test]
        public void TestVmpcPrng()
        {
            SecureRandom random = new SecureRandom(new VmpcRandomGenerator());
            random.SetSeed(random.GenerateSeed(32));

            CheckSecureRandom(random);
        }

        [Test]
        public void TestX931()
        {
            SecureRandom random = new X931SecureRandomBuilder().Build(AesUtilities.CreateEngine(), new KeyParameter(new byte[16]), false);

            CheckSecureRandom(random);
        }


        private static void CheckSecureRandom(SecureRandom random)
        {
            // Note: This will periodically (< 1e-6 probability) give a false alarm.
            // That's randomness for you!
            Assert.IsTrue(RunChiSquaredTests(random), "Chi2 test detected possible non-randomness");
        }

        private static bool RunChiSquaredTests(SecureRandom random)
        {
            {
                int passes = 0;

                for (int tries = 0; tries < 100; ++tries)
                {
                    double chi2 = MeasureChiSquared(random, 1000);

                    // 255 degrees of freedom in test => Q ~ 10.0% for 285
                    if (chi2 < 285.0)
                    {
                        ++passes;
                    }
                }

                if (passes <= 75)
                    return false;
            }

            // NOTE: .NET Core 2.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            {
                int passes = 0;

                for (int tries = 0; tries < 100; ++tries)
                {
                    double chi2 = MeasureChiSquaredSpan(random, 1000);

                    // 255 degrees of freedom in test => Q ~ 10.0% for 285
                    if (chi2 < 285.0)
                    {
                        ++passes;
                    }
                }

                if (passes <= 75)
                    return false;
            }
#endif

            return true;
        }

        private static double MeasureChiSquared(SecureRandom random, int rounds)
        {
            byte[] opts = random.GenerateSeed(2);
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

            byte mask = opts[0];
            for (int i = 0; i < rounds; ++i)
            {
                random.NextBytes(bs);

                for (int b = 0; b < 256; ++b)
                {
                    ++counts[bs[b] ^ mask];
                }

                ++mask;
            }

            byte shift = opts[1];
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

        // NOTE: .NET Core 2.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static double MeasureChiSquaredSpan(SecureRandom random, int rounds)
        {
            Span<byte> opts = stackalloc byte[2];
            random.GenerateSeed(opts);

            Span<int> counts = stackalloc int[256];

            Span<byte> bs = stackalloc byte[256];
            for (int i = 0; i < rounds; ++i)
            {
                random.NextBytes(bs);

                for (int b = 0; b < 256; ++b)
                {
                    ++counts[bs[b]];
                }
            }

            byte mask = opts[0];
            for (int i = 0; i < rounds; ++i)
            {
                random.NextBytes(bs);

                for (int b = 0; b < 256; ++b)
                {
                    ++counts[bs[b] ^ mask];
                }

                ++mask;
            }

            byte shift = opts[1];
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
                double diff = ((double)counts[k]) - total;
                double diff2 = diff * diff;

                chi2 += diff2;
            }

            chi2 /= total;

            return chi2;
        }
#endif

        private abstract class TestRandomGenerator
            : IRandomGenerator
        {
            public virtual void AddSeedMaterial(byte[] seed)
            {
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public void AddSeedMaterial(ReadOnlySpan<byte> inSeed)
            {
            }
#endif

            public virtual void AddSeedMaterial(long seed)
            {
            }

            public virtual void NextBytes(byte[] bytes)
            {
                NextBytes(bytes, 0, bytes.Length);
            }

            public abstract void NextBytes(byte[] bytes, int start, int len);

            // NOTE: .NET Core 2.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public abstract void NextBytes(Span<byte> bytes);
#endif
        }

        private sealed class FixedRandomGenerator
            : TestRandomGenerator
        {
            private readonly byte b;

            internal FixedRandomGenerator(byte b)
            {
                this.b = b;
            }

            public override void NextBytes(byte[] bytes, int start, int len)
            {
                Arrays.Fill(bytes, start, start + len, b);
            }

            // NOTE: .NET Core 2.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void NextBytes(Span<byte> bytes)
            {
                bytes.Fill(b);
            }
#endif
        }
    }
}
