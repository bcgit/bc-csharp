using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Frodo;

namespace Org.BouncyCastle.Pqc.Crypto.NtruPrime
{
    public class NtruPrimeKemExtractor : IEncapsulatedSecretExtractor
    {
        private NtruPrimeEngine _pEngine;
        private NtruPrimeKeyParameters _pKey;

        public NtruPrimeKemExtractor(NtruPrimeKeyParameters privParams)
        {
            this._pKey = privParams;
            InitCipher(_pKey.Parameters);
        }

        private void InitCipher(NtruPrimeParameters param)
        {
            _pEngine = param.PEngine;
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] session_key = new byte[_pEngine.SessionKeySize];
            _pEngine.kem_dec(session_key, encapsulation, ((NtruPrimePrivateKeyParameters)_pKey).privKey);
            return session_key;
        }

        public int GetInputSize()
        {
            return _pEngine.CipherTextSize;
        }
        
    }
}
