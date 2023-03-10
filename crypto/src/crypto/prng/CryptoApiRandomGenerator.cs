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

        public CryptoApiRandomGenerator()
            : this(RandomNumberGenerator.Create())
        {
        }

        public CryptoApiRandomGenerator(RandomNumberGenerator randomNumberGenerator)
        {
            m_randomNumberGenerator = randomNumberGenerator ??
                throw new ArgumentNullException(nameof(randomNumberGenerator));
        }

        #region IRandomGenerator Members

        public void AddSeedMaterial(byte[] seed)
        {
            // We don't care about the seed
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void AddSeedMaterial(ReadOnlySpan<byte> inSeed)
        {
            // We don't care about the seed
        }
#endif

        public void AddSeedMaterial(long seed)
        {
            // We don't care about the seed
        }

        public void NextBytes(byte[] bytes)
        {
            m_randomNumberGenerator.GetBytes(bytes);
        }

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
        public void NextBytes(Span<byte> bytes)
        {
            m_randomNumberGenerator.GetBytes(bytes);
        }
#endif

        #endregion

        #region IDisposable Members

        public void Dispose()
        {
            m_randomNumberGenerator.Dispose();
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
