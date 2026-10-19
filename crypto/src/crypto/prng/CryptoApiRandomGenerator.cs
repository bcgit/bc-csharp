using System;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Crypto.Prng
{
    /// <summary>
    /// Uses RandomNumberGenerator.Create() to get randomness generator
    /// </summary>
    public sealed class CryptoApiRandomGenerator
        : IRandomGenerator, IDisposable
    {
        private readonly RandomNumberGenerator m_randomNumberGenerator;

        /// <summary>Create a new <see cref="CryptoApiRandomGenerator"/>.</summary>
        public CryptoApiRandomGenerator()
            : this(RandomNumberGenerator.Create())
        {
        }

        /// <summary>Create a new <see cref="CryptoApiRandomGenerator"/>.</summary>
        /// <param name="randomNumberGenerator">The random number generator.</param>
        public CryptoApiRandomGenerator(RandomNumberGenerator randomNumberGenerator)
        {
            m_randomNumberGenerator = randomNumberGenerator ??
                throw new ArgumentNullException(nameof(randomNumberGenerator));
        }

        #region IRandomGenerator Members

        /// <inheritdoc/>
        public void AddSeedMaterial(byte[] seed)
        {
            // We don't care about the seed
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void AddSeedMaterial(ReadOnlySpan<byte> inSeed)
        {
            // We don't care about the seed
        }
#endif

        /// <inheritdoc/>
        public void AddSeedMaterial(long seed)
        {
            // We don't care about the seed
        }

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes)
        {
            m_randomNumberGenerator.GetBytes(bytes);
        }

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes, int start, int len)
        {
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
            m_randomNumberGenerator.GetBytes(bytes, start, len);
#else
            if (start < 0)
                throw new ArgumentException("Start offset cannot be negative", nameof(start));
            if (start > bytes.Length - len)
                throw new ArgumentException("Byte array too small for requested offset and length");

            if (bytes.Length == len && start == 0)
            {
                NextBytes(bytes);
            }
            else
            {
                byte[] tmp = new byte[len];
                NextBytes(tmp);
                tmp.CopyTo(bytes, start);
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void NextBytes(Span<byte> bytes)
        {
            m_randomNumberGenerator.GetBytes(bytes);
        }
#endif

        #endregion

        #region IDisposable Members

        /// <summary>Release the underlying random number generator.</summary>
        public void Dispose()
        {
            m_randomNumberGenerator.Dispose();
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
