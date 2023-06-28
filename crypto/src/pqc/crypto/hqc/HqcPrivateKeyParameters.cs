using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public sealed class HqcPrivateKeyParameters
        : HqcKeyParameters
    {
        private byte[] sk;

        public HqcPrivateKeyParameters(HqcParameters param, byte[] sk) : base(true, param)
        {
            this.sk = Arrays.Clone(sk);
        }

        public byte[] PrivateKey => Arrays.Clone(sk);
        public byte[] GetEncoded()
        {
            return PrivateKey;
        }
    }
}
