using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    public sealed class PicnicPrivateKeyParameters
        : PicnicKeyParameters
    {
        private readonly byte[] m_privateKey;

        public PicnicPrivateKeyParameters(PicnicParameters parameters, byte[] skEncoded)
            : base(true, parameters)
        {
            m_privateKey = Arrays.Clone(skEncoded);
        }

        public byte[] GetEncoded()
        {
            return Arrays.Clone(m_privateKey);
        }
    }
}
