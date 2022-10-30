using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Sike
{
    [Obsolete("Will be removed")]
    public sealed class SikeKemGenerator
        : IEncapsulatedSecretGenerator
    {
        // the source of randomness
        private readonly SecureRandom sr;

        public SikeKemGenerator(SecureRandom random)
        {
            this.sr = CryptoServicesRegistrar.GetSecureRandom(random);
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            SikePublicKeyParameters key = (SikePublicKeyParameters)recipientKey;
            SikeEngine engine = key.Parameters.Engine;

            return GenerateEncapsulated(recipientKey, engine.GetDefaultSessionKeySize());
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey, uint sessionKeySizeInBits)
        {
            Console.Error.WriteLine("WARNING: the SIKE algorithm is only for research purposes, insecure");
            SikePublicKeyParameters key = (SikePublicKeyParameters)recipientKey;
            SikeEngine engine = key.Parameters.Engine;
            byte[] cipher_text = new byte[engine.GetCipherTextSize()];
            byte[] sessionKey = new byte[sessionKeySizeInBits / 8];
            engine.crypto_kem_enc(cipher_text, sessionKey, key.GetPublicKey(), sr);
            return new SecretWithEncapsulationImpl(sessionKey, cipher_text);
        }
    }
}
