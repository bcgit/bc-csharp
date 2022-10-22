using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    public sealed class SikePrivateKeyParameters
        : SikeKeyParameters
    {
        private readonly byte[] privateKey;

        public SikePrivateKeyParameters(SikeParameters param, byte[] privateKey)
            : base(true, param)
        {
            this.privateKey = Arrays.Clone(privateKey);
        }

        public byte[] GetEncoded()
        {
            return Arrays.Clone(privateKey);
        }

        public byte[] GetPrivateKey()
        {
            return Arrays.Clone(privateKey);
        }
    }
}
