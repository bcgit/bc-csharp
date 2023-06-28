using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public sealed class FalconPublicKeyParameters
        : FalconKeyParameters
    {
        private readonly byte[] publicKey;

        public FalconPublicKeyParameters(FalconParameters parameters, byte[] h)
            : base(false, parameters)
        {
            this.publicKey = Arrays.Clone(h);
        }

        public byte[] GetEncoded()
        {
            return Arrays.Clone(publicKey);
        }
    }
}
