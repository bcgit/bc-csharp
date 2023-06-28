using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public sealed class SNtruPrimePrivateKeyParameters
        : SNtruPrimeKeyParameters
    {
        internal byte[] privKey;

        public SNtruPrimePrivateKeyParameters(SNtruPrimeParameters primeParameters, byte[] privKey)
            : base(true, primeParameters)
        {
            this.privKey = Arrays.Clone(privKey);
        }

        public byte[] GetPrivateKey()
        {
            return Arrays.Clone(privKey);
        }
        
        public byte[] GetEncoded()
        {
            return GetPrivateKey();
        }
    }
}
