using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public sealed class SaberPublicKeyParameters
        : SaberKeyParameters
    {
        public readonly byte[] publicKey;

        public SaberPublicKeyParameters(SaberParameters parameters, byte[] publicKey)
            : base(false, parameters)
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
