using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public sealed class SNtruPrimePublicKeyParameters
        : SNtruPrimeKeyParameters
    {
        internal byte[] pubKey;

        public SNtruPrimePublicKeyParameters(SNtruPrimeParameters primeParameters, byte[] pubKey) : base(false, primeParameters)
        {
            this.pubKey = Arrays.Clone(pubKey);
        }

        public byte[] GetPublicKey()
        {
            return Arrays.Clone(pubKey);
        }

        public byte[] GetEncoded()
        {
            return GetPublicKey();
        }
    }
}
