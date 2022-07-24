using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public class NtruKeyGenerationParameters : KeyGenerationParameters
    {
        private NtruPrimeParameters _pParameters;
        
        public NtruKeyGenerationParameters(SecureRandom random, NtruPrimeParameters ntruPParameters) : base(random,256)
        {
            this._pParameters = ntruPParameters;
        }

        public NtruPrimeParameters PParameters => _pParameters;

    }
}
