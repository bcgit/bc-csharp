using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public class NtruPrimeKeyParameters : AsymmetricKeyParameter
    {
        private NtruPrimeParameters _pParameters;
        
        public NtruPrimeKeyParameters(bool isPrivate, NtruPrimeParameters pParameters) : base(isPrivate)
        {
            this._pParameters = pParameters;
        }

        public NtruPrimeParameters Parameters => _pParameters;

    }
}
