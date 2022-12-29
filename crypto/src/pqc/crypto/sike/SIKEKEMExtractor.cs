using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    [Obsolete("Will be removed")]
    public sealed class SikeKemExtractor
        : IEncapsulatedSecretExtractor
    {
        private readonly SikeKeyParameters key;

        private SikeEngine engine;

        public SikeKemExtractor(SikePrivateKeyParameters privParams)
        {
            this.key = privParams;
            InitCipher(key.Parameters);
        }

        private void InitCipher(SikeParameters param)
        {
            engine = param.GetEngine();
            SikePrivateKeyParameters privateParams = (SikePrivateKeyParameters)key;
            //todo: add compression check
        }

        public byte[] ExtractSecret(byte[] encapsulation)
        {
            return ExtractSecret(encapsulation, (int)engine.GetDefaultSessionKeySize());
        }

        public byte[] ExtractSecret(byte[] encapsulation, int sessionKeySizeInBits)
        {
            Console.Error.WriteLine("WARNING: the SIKE algorithm is only for research purposes, insecure");
            byte[] session_key = new byte[sessionKeySizeInBits / 8];
            engine.crypto_kem_dec(session_key, encapsulation, ((SikePrivateKeyParameters)key).GetPrivateKey());
            return session_key;
        }

        public int EncapsulationLength => (int)engine.GetCipherTextSize();
    }
}
