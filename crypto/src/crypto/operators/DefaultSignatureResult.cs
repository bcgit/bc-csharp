using System;

namespace Org.BouncyCastle.Crypto.Operators
{
    /// <summary>The result of a signature calculation.</summary>
    public sealed class DefaultSignatureResult
        : IBlockResult
    {
        private readonly ISigner m_signer;

        /// <summary>Create a new <see cref="DefaultSignatureResult"/>.</summary>
        /// <param name="signer">The signer.</param>
        public DefaultSignatureResult(ISigner signer)
        {
            m_signer = signer;
        }

        /// <inheritdoc/>
        public byte[] Collect() => m_signer.GenerateSignature();

        /// <inheritdoc/>
        public int Collect(byte[] buf, int off)
        {
            byte[] signature = Collect();
            signature.CopyTo(buf, off);
            return signature.Length;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public int Collect(Span<byte> output)
        {
            byte[] signature = Collect();
            signature.CopyTo(output);
            return signature.Length;
        }
#endif

        /// <inheritdoc/>
        public int GetMaxResultLength() => m_signer.GetMaxSignatureSize();
    }
}
