using System;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public class NtruPrimePrivateKeyParameters : NtruPrimeKeyParameters
    {
        internal byte[] privKey;

        public NtruPrimePrivateKeyParameters(NtruPrimeParameters pParameters, byte[] privKey) : base(true, pParameters)
        {
            this.privKey = Arrays.Clone(privKey);
        }
        
        public byte[] GetEncoded()
        {
            return Arrays.Clone(privKey);
        }
    }
}
