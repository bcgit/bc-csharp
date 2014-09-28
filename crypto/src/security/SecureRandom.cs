using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security
{
    public class SecureRandom
        : Random
    {
        // Note: all objects of this class should be deriving their random data from
        // a single generator appropriate to the digest being used.
        private static readonly IRandomGenerator sha1Generator = new DigestRandomGenerator(new Sha1Digest());
        private static readonly IRandomGenerator sha256Generator = new DigestRandomGenerator(new Sha256Digest());

        private static readonly SecureRandom[] master = { null };
        private static SecureRandom Master
        {
            get
            {
                if (master[0] == null)
                {
                    SecureRandom sr = master[0] = new SecureRandom(sha256Generator);

                    // Even though Ticks has at most 8 or 14 bits of entropy, there's no harm in adding it.
                    sr.SetSeed(DateTime.Now.Ticks);
                    // In addition to Ticks and ThreadedSeedGenerator, also seed from CryptoApiRandomGenerator
                    CryptoApiRandomGenerator systemRNG = new CryptoApiRandomGenerator();
                    byte[] systemSeed = new byte[32];
                    systemRNG.NextBytes(systemSeed);
                    sr.SetSeed(systemSeed);
                    Array.Clear(systemSeed,0,systemSeed.Length);
                    // 32 will be enough when ThreadedSeedGenerator is fixed.  Until then, ThreadedSeedGenerator returns low
                    // entropy, and this is not sufficient to be secure. http://www.bouncycastle.org/csharpdevmailarchive/msg00814.html
                    sr.SetSeed(new ThreadedSeedGenerator().GenerateSeed(32, true));
                }

                return master[0];
            }
        }

        public static SecureRandom GetInstance(
            string algorithm)
        {
            // TODO Support all digests more generally, by stripping PRNG and calling DigestUtilities?
            string drgName = Platform.ToUpperInvariant(algorithm);

            if (drgName == "SHA1PRNG")
            {
                SecureRandom newPrng = new SecureRandom(sha1Generator);
                newPrng.SetSeed(GetSeed(20));
                return newPrng;
            }
            else if (drgName == "SHA256PRNG")
            {
                SecureRandom newPrng = new SecureRandom(sha256Generator);
                newPrng.SetSeed(GetSeed(32));
                return newPrng;
            }

            throw new ArgumentException("Unrecognised PRNG algorithm: " + algorithm, "algorithm");
        }

        public static byte[] GetSeed(
            int length)
        {
            return Master.GenerateSeed(length);
        }

        protected IRandomGenerator generator;

        public SecureRandom()
            : this(sha1Generator)
        {
            SetSeed(GetSeed(20));	// 20 bytes because this is sha1Generator
        }

        public SecureRandom(
            byte[] inSeed)
            : this(sha1Generator)
        {
            SetSeed(inSeed);
        }

        /// <summary>Use the specified instance of IRandomGenerator as random source.</summary>
        /// <remarks>
        /// This constructor performs no seeding of either the <c>IRandomGenerator</c> or the
        /// constructed <c>SecureRandom</c>. It is the responsibility of the client to provide
        /// proper seed material as necessary/appropriate for the given <c>IRandomGenerator</c>
        /// implementation.
        /// </remarks>
        /// <param name="generator">The source to generate all random bytes from.</param>
        public SecureRandom(
            IRandomGenerator generator)
            : base(0)
        {
            this.generator = generator;
        }

        public virtual byte[] GenerateSeed(
            int length)
        {
            SetSeed(DateTime.Now.Ticks);

            byte[] rv = new byte[length];
            NextBytes(rv);
            return rv;
        }

        public virtual void SetSeed(
            byte[] inSeed)
        {
            generator.AddSeedMaterial(inSeed);
        }

        public virtual void SetSeed(
            long seed)
        {
            generator.AddSeedMaterial(seed);
        }

        public override int Next()
        {
            for (;;)
            {
                int i = NextInt() & int.MaxValue;

                if (i != int.MaxValue)
                    return i;
            }
        }

        public override int Next(
            int maxValue)
        {
            if (maxValue < 2)
            {
                if (maxValue < 0)
                    throw new ArgumentOutOfRangeException("maxValue", "cannot be negative");

                return 0;
            }

            // Test whether maxValue is a power of 2
            if ((maxValue & -maxValue) == maxValue)
            {
                int val = NextInt() & int.MaxValue;
                long lr = ((long) maxValue * (long) val) >> 31;
                return (int) lr;
            }

            int bits, result;
            do
            {
                bits = NextInt() & int.MaxValue;
                result = bits % maxValue;
            }
            while (bits - result + (maxValue - 1) < 0); // Ignore results near overflow

            return result;
        }

        public override int Next(
            int	minValue,
            int	maxValue)
        {
            if (maxValue <= minValue)
            {
                if (maxValue == minValue)
                    return minValue;

                throw new ArgumentException("maxValue cannot be less than minValue");
            }

            int diff = maxValue - minValue;
            if (diff > 0)
                return minValue + Next(diff);

            for (;;)
            {
                int i = NextInt();

                if (i >= minValue && i < maxValue)
                    return i;
            }
        }

        public override void NextBytes(
            byte[] buffer)
        {
            generator.NextBytes(buffer);
        }

        public virtual void NextBytes(
            byte[]	buffer,
            int		start,
            int		length)
        {
            generator.NextBytes(buffer, start, length);
        }

        private static readonly double DoubleScale = System.Math.Pow(2.0, 64.0);

        public override double NextDouble()
        {
            return Convert.ToDouble((ulong) NextLong()) / DoubleScale;
        }

        public virtual int NextInt()
        {
            byte[] intBytes = new byte[4];
            NextBytes(intBytes);

            int result = 0;
            for (int i = 0; i < 4; i++)
            {
                result = (result << 8) + (intBytes[i] & 0xff);
            }

            return result;
        }

        public virtual long NextLong()
        {
            return ((long)(uint) NextInt() << 32) | (long)(uint) NextInt();
        }
    }
}
