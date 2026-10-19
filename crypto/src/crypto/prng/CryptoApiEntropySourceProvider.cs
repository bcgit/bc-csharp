using System;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Crypto.Prng
{
    /// <summary>
    /// An entropy source provider that draws entropy from the platform's cryptographic random number generator.
    /// </summary>
    public class CryptoApiEntropySourceProvider
        :   IEntropySourceProvider
    {
        private readonly RandomNumberGenerator mRng;
        private readonly bool mPredictionResistant;

        /// <summary>Create a new <see cref="CryptoApiEntropySourceProvider"/>.</summary>
        public CryptoApiEntropySourceProvider()
            : this(RandomNumberGenerator.Create(), true)
        {
        }

        /// <summary>Create a new <see cref="CryptoApiEntropySourceProvider"/>.</summary>
        /// <param name="rng">The rng.</param>
        /// <param name="isPredictionResistant">true if is prediction resistant, false otherwise.</param>
        public CryptoApiEntropySourceProvider(RandomNumberGenerator rng, bool isPredictionResistant)
        {
            mRng = rng ?? throw new ArgumentNullException(nameof(rng));
            mPredictionResistant = isPredictionResistant;
        }

        /// <inheritdoc/>
        public IEntropySource Get(int bitsRequired)
        {
            return new CryptoApiEntropySource(mRng, mPredictionResistant, bitsRequired);
        }

        private class CryptoApiEntropySource
            :   IEntropySource
        {
            private readonly RandomNumberGenerator mRng;
            private readonly bool mPredictionResistant;
            private readonly int mEntropySize;

            internal CryptoApiEntropySource(RandomNumberGenerator rng, bool predictionResistant, int entropySize)
            {
                this.mRng = rng;
                this.mPredictionResistant = predictionResistant;
                this.mEntropySize = entropySize;
            }

            #region IEntropySource Members

            bool IEntropySource.IsPredictionResistant
            {
                get { return mPredictionResistant; }
            }

            byte[] IEntropySource.GetEntropy()
            {
                byte[] result = new byte[(mEntropySize + 7) / 8];
                mRng.GetBytes(result);
                return result;
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int IEntropySource.GetEntropy(Span<byte> output)
            {
                int length = System.Math.Min(output.Length, (mEntropySize + 7) / 8);
                mRng.GetBytes(output[..length]);
                return length;
            }
#endif

            int IEntropySource.EntropySize
            {
                get { return mEntropySize; }
            }

            #endregion
        }
    }
}
