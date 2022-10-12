using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public class SaberPrivateKeyParameters
        : SaberKeyParameters
    {
        private byte[] privateKey;

        public byte[] GetPrivateKey()
        {
            return Arrays.Clone(privateKey);
        }

        public SaberPrivateKeyParameters(SaberParameters parameters, byte[] privateKey)
            : base(true, parameters)
        {
            this.privateKey = Arrays.Clone(privateKey);
        }

        public byte[] GetEncoded()
        {
            return Arrays.Clone(privateKey);
        }
    }
}