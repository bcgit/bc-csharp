using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /// <summary>Wrapper class that reduces the output length of a particular digest to only the first n bytes of
    /// the digest function.</summary>
    // TODO[api] Make sealed
    public class ShortenedDigest
        : IDigest
    {
        private readonly IDigest m_baseDigest;
        private readonly int m_length;

        /// <summary>Base constructor.</summary>
        /// <param name="baseDigest">The underlying digest to use.</param>
        /// <param name="length">The length, in bytes, of the output of DoFinal.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="baseDigest"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">If <paramref name="length"/> is less than 1, or greater
        /// than the digest size of <paramref name="baseDigest"/>.</exception>
        public ShortenedDigest(IDigest baseDigest, int length)
        {
            if (baseDigest == null)
                throw new ArgumentNullException(nameof(baseDigest));
            if (length < 1)
                throw new ArgumentOutOfRangeException(nameof(length));
            if (length > baseDigest.GetDigestSize())
                throw new ArgumentOutOfRangeException(nameof(length),
                    "baseDigest output not large enough to support length");

            m_baseDigest = baseDigest;
            m_length = length;
        }

        public string AlgorithmName => m_baseDigest.AlgorithmName + "(" + m_length * 8 + ")";

        public int GetDigestSize() => m_length;

        public void Update(byte input) => m_baseDigest.Update(input);

        public void BlockUpdate(byte[] input, int inOff, int inLen) => m_baseDigest.BlockUpdate(input, inOff, inLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input) => m_baseDigest.BlockUpdate(input);
#endif

        public int DoFinal(byte[] output, int outOff)
        {
            // Checked up front so that nothing can throw between filling the temporary and wiping it.
            Check.OutputLength(output, outOff, m_length, "output buffer too short");

            byte[] tmp = new byte[m_baseDigest.GetDigestSize()];

            m_baseDigest.DoFinal(tmp, 0);

            Array.Copy(tmp, 0, output, outOff, m_length);

            // The caller asked for a shortened digest, so don't leave the discarded part of it behind.
            Arrays.ZeroMemory(tmp);

            return m_length;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            // Checked up front so that nothing can throw between filling the temporary and wiping it.
            Check.OutputLength(output, m_length, "output buffer too short");

            int baseDigestSize = m_baseDigest.GetDigestSize();
            Span<byte> tmp = baseDigestSize <= 128
                ? stackalloc byte[baseDigestSize]
                : new byte[baseDigestSize];

            m_baseDigest.DoFinal(tmp);

            tmp[..m_length].CopyTo(output);

            // The caller asked for a shortened digest, so don't leave the discarded part of it behind.
            Arrays.ZeroMemory(tmp);

            return m_length;
        }
#endif

        public void Reset() => m_baseDigest.Reset();

        public int GetByteLength() => m_baseDigest.GetByteLength();
    }
}
