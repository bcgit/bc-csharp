using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    public sealed class SikePublicKeyParameters
        : SikeKeyParameters
    {
        public readonly byte[] publicKey;

        public SikePublicKeyParameters(SikeParameters param, byte[] publicKey)
            : base(false, param)
        {
            this.publicKey = Arrays.Clone(publicKey);
        }

        public byte[] GetEncoded()
        {
            return Arrays.Clone(publicKey);
        }

        public byte[] GetPublicKey()
        {
            return Arrays.Clone(publicKey);
        }
    }
}
