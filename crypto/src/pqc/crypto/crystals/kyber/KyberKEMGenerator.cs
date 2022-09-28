using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public sealed class KyberKemGenerator
        : IEncapsulatedSecretGenerator
    {
        // the source of randomness
        private SecureRandom m_random;

        public KyberKemGenerator(SecureRandom random)
        {
            m_random = random;
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            KyberPublicKeyParameters key = (KyberPublicKeyParameters) recipientKey;
            KyberEngine engine = key.Parameters.Engine;
            engine.Init(m_random);
            byte[] cipherText = new byte[engine.CryptoCipherTextBytes];
            byte[] sessionKey = new byte[engine.CryptoBytes];
            engine.KemEncrypt(cipherText, sessionKey, key.GetEncoded());
            return new SecretWithEncapsulationImpl(sessionKey, cipherText);
        }

        private sealed class SecretWithEncapsulationImpl
            : ISecretWithEncapsulation
        {
            private volatile bool m_hasBeenDestroyed = false;

            private byte[] m_sessionKey;
            private byte[] m_cipherText;

            internal SecretWithEncapsulationImpl(byte[] sessionKey, byte[] cipher_text)
            {
                m_sessionKey = sessionKey;
                m_cipherText = cipher_text;
            }

            public byte[] GetSecret()
            {
                CheckDestroyed();

                return Arrays.Clone(m_sessionKey);
            }

            public byte[] GetEncapsulation()
            {
                CheckDestroyed();

                return Arrays.Clone(m_cipherText);
            }

            public void Dispose()
            {
                if (!m_hasBeenDestroyed)
                {
                    m_hasBeenDestroyed = true;
                    Arrays.Clear(m_sessionKey);
                    Arrays.Clear(m_cipherText);
                }
            }

            internal bool IsDestroyed()
            {
                return m_hasBeenDestroyed;
            }

            private void CheckDestroyed()
            {
                if (IsDestroyed())
                {
                    throw new ArgumentException("data has been destroyed");
                }
            }
        }
    }
}