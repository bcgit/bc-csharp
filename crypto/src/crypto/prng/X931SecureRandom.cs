using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Prng
{
    /// <summary>A source of randomness based on the ANSI X9.31 random number generator.</summary>
    public class X931SecureRandom
        :   SecureRandom
    {
        private readonly bool           mPredictionResistant;
        private readonly SecureRandom   mRandomSource;
        private readonly X931Rng        mDrbg;

        internal X931SecureRandom(SecureRandom randomSource, X931Rng drbg, bool predictionResistant)
            : base(null)
        {
            this.mRandomSource = randomSource;
            this.mDrbg = drbg;
            this.mPredictionResistant = predictionResistant;
        }

        /// <inheritdoc/>
        public override void SetSeed(byte[] seed)
        {
            lock (this)
            {
                if (mRandomSource != null)
                {
                    this.mRandomSource.SetSeed(seed);
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void SetSeed(Span<byte> seed)
        {
            lock (this)
            {
                if (mRandomSource != null)
                {
                    this.mRandomSource.SetSeed(seed);
                }
            }
        }
#endif

        /// <inheritdoc/>
        public override void SetSeed(long seed)
        {
            lock (this)
            {
                // this will happen when SecureRandom() is created
                if (mRandomSource != null)
                {
                    this.mRandomSource.SetSeed(seed);
                }
            }
        }

        /// <inheritdoc/>
        public override void NextBytes(byte[] bytes)
        {
            NextBytes(bytes, 0, bytes.Length);
        }

        /// <inheritdoc/>
        public override void NextBytes(byte[] buf, int off, int len)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            NextBytes(buf.AsSpan(off, len));
#else
            lock (this)
            {
                // check if a reseed is required...
                if (mDrbg.Generate(buf, off, len, mPredictionResistant) < 0)
                {
                    mDrbg.Reseed();
                    mDrbg.Generate(buf, off, len, mPredictionResistant);
                }
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void NextBytes(Span<byte> buffer)
        {
            lock (this)
            {
                // check if a reseed is required...
                if (mDrbg.Generate(buffer, mPredictionResistant) < 0)
                {
                    mDrbg.Reseed();
                    mDrbg.Generate(buffer, mPredictionResistant);
                }
            }
        }
#endif

        /// <inheritdoc/>
        public override byte[] GenerateSeed(int numBytes)
        {
            return EntropyUtilities.GenerateSeed(mDrbg.EntropySource, numBytes);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void GenerateSeed(Span<byte> seed)
        {
            EntropyUtilities.GenerateSeed(mDrbg.EntropySource, seed);
        }
#endif
    }
}
