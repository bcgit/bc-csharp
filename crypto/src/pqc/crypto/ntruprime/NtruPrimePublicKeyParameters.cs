using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public class NtruPrimePublicKeyParameters : NtruPrimeKeyParameters
    {
        internal byte[] pubKey;

        public byte[] GetEncoded()
        {
            return Arrays.Clone(pubKey);
        }

        public NtruPrimePublicKeyParameters(NtruPrimeParameters pParameters, byte[] pubKey) : base(false,pParameters)
        {
            this.pubKey = Arrays.Clone(pubKey);
        }
    }
}
