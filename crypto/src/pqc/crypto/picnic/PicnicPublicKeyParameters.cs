using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    public sealed class PicnicPublicKeyParameters
        : PicnicKeyParameters
    {
        private readonly byte[] m_publicKey;

        public PicnicPublicKeyParameters(PicnicParameters parameters, byte[] pkEncoded)
            : base(false, parameters)
        {
            m_publicKey = Arrays.Clone(pkEncoded);
        }

        public byte[] GetEncoded()
        {
            return Arrays.Clone(m_publicKey);
        }
    }
}
