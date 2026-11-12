using System;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Security.Cryptography;
#endif
using System.Threading;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Security
{
    /// <summary>A cryptographically strong random number generator, built on an <see cref="IRandomGenerator"/>.
    /// </summary>
    public class SecureRandom
        : Random
    {
        private static long counter = DateTime.UtcNow.Ticks;

        private static long NextCounterValue() => Interlocked.Increment(ref counter);

#if !(NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
        private static readonly SecureRandom MasterRandom = new SecureRandom(new CryptoApiRandomGenerator());
#endif
        internal static readonly SecureRandom ArbitraryRandom = new SecureRandom(new VmpcRandomGenerator(), 16);

        private static DigestRandomGenerator CreatePrng(string digestName, bool autoSeed)
        {
            IDigest digest = DigestUtilities.GetDigest(digestName);
            if (digest == null)
                return null;
            DigestRandomGenerator prng = new DigestRandomGenerator(digest);
            if (autoSeed)
            {
                AutoSeed(prng, 2 * digest.GetDigestSize());
            }
            return prng;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // System.Buffers.SpanAction<byte, in SecureRandom>
        /// <summary>Fill the buffer with random bytes from the given source.</summary>
        /// <param name="buffer">The buffer to fill.</param>
        /// <param name="secureRandom">The source of randomness.</param>
        public static void Fill(Span<byte> buffer, SecureRandom secureRandom) => secureRandom.NextBytes(buffer);
#endif

        /// <summary>Return a new array of random bytes from the given source.</summary>
        /// <param name="secureRandom">The source of randomness.</param>
        /// <param name="length">The number of bytes.</param>
        public static byte[] GetNextBytes(SecureRandom secureRandom, int length)
        {
            byte[] result = new byte[length];
            secureRandom.NextBytes(result);
            return result;
        }

        /// <summary>
        /// Create and auto-seed an instance based on the given algorithm.
        /// </summary>
        /// <remarks>Equivalent to GetInstance(algorithm, true)</remarks>
        /// <param name="algorithm">e.g. "SHA256PRNG"</param>
        public static SecureRandom GetInstance(string algorithm) => GetInstance(algorithm, autoSeed: true);

        /// <summary>
        /// Create an instance based on the given algorithm, with optional auto-seeding
        /// </summary>
        /// <param name="algorithm">e.g. "SHA256PRNG"</param>
        /// <param name="autoSeed">If true, the instance will be auto-seeded.</param>
        public static SecureRandom GetInstance(string algorithm, bool autoSeed)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            if (algorithm.EndsWith("PRNG", StringComparison.OrdinalIgnoreCase))
            {
                string digestName = algorithm.Substring(0, algorithm.Length - "PRNG".Length);

                DigestRandomGenerator prng = CreatePrng(digestName, autoSeed);
                if (prng != null)
                    return new SecureRandom(prng);
            }

            throw new ArgumentException("Unrecognised PRNG algorithm: " + algorithm, "algorithm");
        }

        /// <summary>The underlying random byte generator.</summary>
        protected readonly IRandomGenerator generator;

        /// <summary>Create an auto-seeded instance based on a SHA-256 digest generator.</summary>
        public SecureRandom()
            : this(CreatePrng("SHA256", autoSeed: true))
        {
        }

        /// <summary>Use the specified instance of IRandomGenerator as random source.</summary>
        /// <remarks>
        /// This constructor performs no seeding of either the <c>IRandomGenerator</c> or the
        /// constructed <c>SecureRandom</c>. It is the responsibility of the client to provide
        /// proper seed material as necessary/appropriate for the given <c>IRandomGenerator</c>
        /// implementation.
        /// </remarks>
        /// <param name="generator">The source to generate all random bytes from.</param>
        public SecureRandom(IRandomGenerator generator)
            : base(0)
        {
            this.generator = generator;
        }

        /// <summary>Use the specified instance of IRandomGenerator as random source, auto-seeding it.</summary>
        /// <param name="generator">The source to generate all random bytes from.</param>
        /// <param name="autoSeedLengthInBytes">The number of bytes of seed material to add to the generator.</param>
        public SecureRandom(IRandomGenerator generator, int autoSeedLengthInBytes)
            : base(0)
        {
            AutoSeed(generator, autoSeedLengthInBytes);

            this.generator = generator;
        }

        /// <summary>Generate seed material from the platform's cryptographic random source.</summary>
        /// <param name="length">The number of bytes.</param>
        public virtual byte[] GenerateSeed(int length)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            byte[] result = new byte[length];
            GenerateSeed(result.AsSpan());
            return result;
#else
            return GetNextBytes(MasterRandom, length);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Fill the buffer with seed material from the platform's cryptographic random source.</summary>
        /// <param name="seed">The buffer to fill.</param>
        public virtual void GenerateSeed(Span<byte> seed) => RandomNumberGenerator.Fill(seed);
#endif

        /// <summary>Add seed material to the underlying generator.</summary>
        /// <param name="seed">The seed material.</param>
        public virtual void SetSeed(byte[] seed) => generator.AddSeedMaterial(seed);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Add seed material to the underlying generator.</summary>
        /// <param name="seed">The seed material.</param>
        public virtual void SetSeed(Span<byte> seed) => generator.AddSeedMaterial(seed);
#endif

        /// <summary>Add seed material to the underlying generator.</summary>
        /// <param name="seed">The seed material.</param>
        public virtual void SetSeed(long seed) => generator.AddSeedMaterial(seed);

        /// <summary>Return a non-negative random integer.</summary>
        public override int Next() => NextInt() & int.MaxValue;

        /// <summary>Return a non-negative random integer less than <paramref name="maxValue"/>.</summary>
        /// <param name="maxValue">The exclusive upper bound.</param>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxValue"/> is negative.</exception>
        public override int Next(int maxValue)
        {
            if (maxValue < 2)
            {
                if (maxValue < 0)
                    throw new ArgumentOutOfRangeException(nameof(maxValue), "cannot be negative");

                return 0;
            }

            int bits;

            // Test whether maxValue is a power of 2
            if ((maxValue & (maxValue - 1)) == 0)
            {
                bits = NextInt() & int.MaxValue;
                return (int)(((long)bits * maxValue) >> 31);
            }

            int result;
            do
            {
                bits = NextInt() & int.MaxValue;
                result = bits % maxValue;
            }
            while (bits - result + (maxValue - 1) < 0); // Ignore results near overflow

            return result;
        }

        /// <summary>Return a random integer in the range from <paramref name="minValue"/> up to, but excluding,
        /// <paramref name="maxValue"/>.</summary>
        /// <param name="minValue">The inclusive lower bound.</param>
        /// <param name="maxValue">The exclusive upper bound.</param>
        /// <exception cref="ArgumentException"><paramref name="maxValue"/> is less than <paramref name="minValue"/>.
        /// </exception>
        public override int Next(int minValue, int maxValue)
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

        /// <summary>Fill the array with random bytes.</summary>
        /// <param name="buf">The array to fill.</param>
        public override void NextBytes(byte[] buf) => generator.NextBytes(buf);

        /// <summary>Fill part of the array with random bytes.</summary>
        /// <param name="buf">The array to fill.</param>
        /// <param name="off">The index of the first byte to fill.</param>
        /// <param name="len">The number of bytes to fill.</param>
        public virtual void NextBytes(byte[] buf, int off, int len) => generator.NextBytes(buf, off, len);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Fill the buffer with random bytes.</summary>
        /// <param name="buffer">The buffer to fill.</param>
        public override void NextBytes(Span<byte> buffer)
        {
            if (generator != null)
            {
                generator.NextBytes(buffer);
            }
            else
            {
                byte[] tmp = new byte[buffer.Length];
                NextBytes(tmp);
                tmp.CopyTo(buffer);
            }
        }
#endif

        private static readonly double DoubleScale = 1.0 / Convert.ToDouble(1L << 53);

        /// <summary>Return a random floating point number in the range from 0.0 up to, but excluding, 1.0.</summary>
        public override double NextDouble()
        {
            ulong x = (ulong)NextLong() >> 11;

            return Convert.ToDouble(x) * DoubleScale;
        }

        /// <summary>Return a random 32-bit integer.</summary>
        public virtual int NextInt()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bytes = stackalloc byte[4];
#else
            byte[] bytes = new byte[4];
#endif
            NextBytes(bytes);
            return (int)Pack.BE_To_UInt32(bytes);
        }

        /// <summary>Return a random 64-bit integer.</summary>
        public virtual long NextLong()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> bytes = stackalloc byte[8];
#else
            byte[] bytes = new byte[8];
#endif
            NextBytes(bytes);
            return (long)Pack.BE_To_UInt64(bytes);
        }

        private static void AutoSeed(IRandomGenerator generator, int seedLength)
        {
            generator.AddSeedMaterial(NextCounterValue());

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> seed = seedLength <= 128
                ? stackalloc byte[seedLength]
                : new byte[seedLength];
            RandomNumberGenerator.Fill(seed);
#else
            byte[] seed = new byte[seedLength];
            MasterRandom.NextBytes(seed);
#endif
            generator.AddSeedMaterial(seed);
        }
    }
}
