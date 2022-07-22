using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.pqc.crypto.NtruP
{
    public class NtruPPublicKeyParameters : NtruPKeyParameters
    {
        public byte[] pubKey;

        public byte[] PublicKey => Arrays.Clone(pubKey);

        public byte[] GetEncoded()
        {
            return PublicKey;
        }

        public NtruPPublicKeyParameters(NtruPParameters pParameters, byte[] pubKey) : base(false,pParameters)
        {
            this.pubKey = Arrays.Clone(pubKey);
        }
    }
}