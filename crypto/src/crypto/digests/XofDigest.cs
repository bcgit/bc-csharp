using System;

namespace Org.BouncyCastle.Crypto.Digests
{
    /// <summary>Wrapper class that fixes the output length of an extendable output function (XOF), so that it can
    /// be used where a digest of that exact size is expected.</summary>
    /// <remarks>The output is squeezed to the requested length, so - unlike <see cref="ShortenedDigest"/>, which
    /// truncates - the length is not limited by the default digest size of the XOF.</remarks>
    internal sealed class XofDigest
        : IDigest
    {
        private readonly IXof m_xof;
        private readonly int m_outputSize;

        /// <param name="xof">The underlying XOF.</param>
        /// <param name="outputSize">The output size, in bytes, of this digest.</param>
        internal XofDigest(IXof xof, int outputSize)
        {
            if (xof == null)
                throw new ArgumentNullException(nameof(xof));
            if (outputSize < 1)
                throw new ArgumentOutOfRangeException(nameof(outputSize));

            m_xof = xof;
            m_outputSize = outputSize;
        }

        // TODO[api] Unfortunately this is IDigest.AlgorithmName; IXof might need its own separate property,
        // although we would prefer to tease the two concepts apart instead.
        public string AlgorithmName => m_xof.AlgorithmName + "@" + (m_outputSize * 8);

        public int GetDigestSize() => m_outputSize;

        public int GetByteLength() => m_xof.GetByteLength();

        public void Update(byte input) => m_xof.Update(input);

        public void BlockUpdate(byte[] input, int inOff, int inLen) => m_xof.BlockUpdate(input, inOff, inLen);

        public int DoFinal(byte[] output, int outOff) => m_xof.OutputFinal(output, outOff, m_outputSize);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input) => m_xof.BlockUpdate(input);

        public int DoFinal(Span<byte> output)
        {
            Check.OutputLength(output, m_outputSize, "output buffer too short");

            return m_xof.OutputFinal(output[..m_outputSize]);
        }
#endif

        public void Reset() => m_xof.Reset();
    }
}
