using System;

using Org.BouncyCastle.Crypto.Prng.Drbg;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Prng
{
    /// <summary>A source of randomness based on the deterministic random bit generators of NIST SP 800-90A.</summary>
    public class SP800SecureRandom
        :   SecureRandom
    {
        private readonly IDrbgProvider  mDrbgProvider;
        private readonly bool           mPredictionResistant;
        private readonly SecureRandom   mRandomSource;
        private readonly IEntropySource mEntropySource;

        private ISP80090Drbg mDrbg;

        internal SP800SecureRandom(SecureRandom randomSource, IEntropySource entropySource, IDrbgProvider drbgProvider,
            bool predictionResistant)
            : base(null)
        {
            this.mRandomSource = randomSource;
            this.mEntropySource = entropySource;
            this.mDrbgProvider = drbgProvider;
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
                if (mDrbg == null)
                {
                    mDrbg = mDrbgProvider.Get(mEntropySource);
                }

                // check if a reseed is required...
                if (mDrbg.Generate(buf, off, len, null, mPredictionResistant) < 0)
                {
                    mDrbg.Reseed(null);
                    mDrbg.Generate(buf, off, len, null, mPredictionResistant);
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
                if (mDrbg == null)
                {
                    mDrbg = mDrbgProvider.Get(mEntropySource);
                }

                // check if a reseed is required...
                if (mDrbg.Generate(buffer, mPredictionResistant) < 0)
                {
                    mDrbg.Reseed(ReadOnlySpan<byte>.Empty);
                    mDrbg.Generate(buffer, mPredictionResistant);
                }
            }
        }
#endif

        /// <inheritdoc/>
        public override byte[] GenerateSeed(int numBytes)
        {
            return EntropyUtilities.GenerateSeed(mEntropySource, numBytes);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void GenerateSeed(Span<byte> seed)
        {
            EntropyUtilities.GenerateSeed(mEntropySource, seed);
        }
#endif

        /// <summary>Force a reseed of the DRBG.</summary>
        /// <param name="additionalInput">optional additional input</param>
        public virtual void Reseed(byte[] additionalInput)
        {
            lock (this)
            {
                if (mDrbg == null)
                {
                    mDrbg = mDrbgProvider.Get(mEntropySource);
                }

                mDrbg.Reseed(additionalInput);
            }
        }
    }
}
