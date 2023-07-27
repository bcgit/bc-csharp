using System;

namespace Org.BouncyCastle.Crypto.Operators
{
    public sealed class DefaultSignatureResult
        : IBlockResult
    {
        private readonly ISigner m_signer;

        public DefaultSignatureResult(ISigner signer)
        {
            m_signer = signer;
        }

        public byte[] Collect() => m_signer.GenerateSignature();

        public int Collect(byte[] buf, int off)
        {
            byte[] signature = Collect();
            signature.CopyTo(buf, off);
            return signature.Length;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Collect(Span<byte> output)
        {
            byte[] signature = Collect();
            signature.CopyTo(output);
            return signature.Length;
        }
#endif

        public int GetMaxResultLength() => m_signer.GetMaxSignatureSize();
    }
}
