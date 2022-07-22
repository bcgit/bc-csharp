using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Frodo;

namespace Org.BouncyCastle.pqc.crypto.NtruP
{
    public class NtruPKEMExtractor : IEncapsulatedSecretExtractor
    {
        private NtruPEngine _pEngine;
        private NtruPKeyParameters _pKey;

        public NtruPKEMExtractor(NtruPKeyParameters privParams)
        {
            this._pKey = privParams;
            InitCipher(_pKey.PParameters);
        }

        private void InitCipher(NtruPParameters param)
        {
            _pEngine = param.PEngine;
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            byte[] session_key = new byte[_pEngine.SessionKeySize];
            _pEngine.kem_dec(session_key, encapsulation, ((NtruPPrivateKeyParameters)_pKey).PrivateKey);
            return session_key;
        }

        public int GetInputSize()
        {
            return _pEngine.CipherTextSize;
        }
        
    }
}