using System;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Digests
{
    /// <summary>
    /// A stand-in digest for data that has already been hashed: the digest value is written to it and returned
    /// unchanged by <c>DoFinal</c>.
    /// </summary>
    public sealed class Prehash
        : IDigest
    {
        public static Prehash ForDigest(IDigest digest) => ForParameters(digest.AlgorithmName, digest.GetDigestSize());

        public static Prehash ForParameters(string digestName, int digestSize) => new Prehash(digestName, digestSize);

        private readonly string m_algorithmName;
        private readonly LimitedBuffer m_buf;

        private Prehash(string algorithmName, int digestSize)
        {
            m_algorithmName = algorithmName;
            m_buf = new LimitedBuffer(digestSize);
        }

        /// <inheritdoc/>
        public string AlgorithmName => m_algorithmName;

        /// <inheritdoc/>
        public int GetByteLength() => throw new NotSupportedException();

        /// <inheritdoc/>
        public int GetDigestSize() => m_buf.Limit;

        /// <inheritdoc/>
        public void Update(byte input) => m_buf.WriteByte(input);

        /// <inheritdoc/>
        public void BlockUpdate(byte[] input, int inOff, int inLen) => m_buf.Write(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void BlockUpdate(ReadOnlySpan<byte> input) => m_buf.Write(input);
#endif

        /// <inheritdoc/>
        public int DoFinal(byte[] output, int outOff)
        {
            try
            {
                if (GetDigestSize() != m_buf.Count)
                    throw new InvalidOperationException("Incorrect prehash size");

                return m_buf.CopyTo(output, outOff);
            }
            finally
            {
                Reset();
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public int DoFinal(Span<byte> output)
        {
            try
            {
                if (GetDigestSize() != m_buf.Count)
                    throw new InvalidOperationException("Incorrect prehash size");

                return m_buf.CopyTo(output);
            }
            finally
            {
                Reset();
            }
        }
#endif

        /// <inheritdoc/>
        public void Reset() => m_buf.Reset();
    }
}
