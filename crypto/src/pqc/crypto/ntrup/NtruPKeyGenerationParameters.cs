using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.pqc.crypto.NtruP
{
    public class NtruKeyGenerationParameters : KeyGenerationParameters
    {
        private NtruPParameters _pParameters;
        
        public NtruKeyGenerationParameters(SecureRandom random, NtruPParameters ntruPParameters) : base(random,256)
        {
            this._pParameters = ntruPParameters;
        }

        public NtruPParameters PParameters => _pParameters;

    }
}