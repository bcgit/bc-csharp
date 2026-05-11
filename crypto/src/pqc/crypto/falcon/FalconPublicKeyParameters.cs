using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public sealed class FalconPublicKeyParameters
        : FalconKeyParameters
    {
        private readonly byte[] m_publicKey;

        public FalconPublicKeyParameters(FalconParameters parameters, byte[] h)
            : base(false, parameters)
        {
            m_publicKey = Arrays.CopyBuffer(h);
        }

        public byte[] GetEncoded() => Arrays.InternalCopyBuffer(m_publicKey);
    }
}
