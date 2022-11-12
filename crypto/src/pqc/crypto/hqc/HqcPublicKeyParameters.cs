using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public sealed class HqcPublicKeyParameters
        : HqcKeyParameters
    {
        private byte[] pk;

        public HqcPublicKeyParameters(HqcParameters param, byte[] pk) : base(false, param)
        {
            this.pk = Arrays.Clone(pk);
        }

        public byte[] PublicKey => Arrays.Clone(pk);

        public byte[] GetEncoded()
        {
            return PublicKey;
        }
    }
}
