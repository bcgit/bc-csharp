using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    public sealed class MLKemGenerator
        : IEncapsulatedSecretGenerator
    {
        // the source of randomness
        private readonly SecureRandom m_random;

        public MLKemGenerator(SecureRandom random)
        {
            m_random = random;
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            MLKemPublicKeyParameters key = (MLKemPublicKeyParameters) recipientKey;
            MLKemEngine engine = key.Parameters.Engine;
            engine.Init(m_random);
            byte[] cipherText = new byte[engine.CryptoCipherTextBytes];
            byte[] sessionKey = new byte[engine.CryptoBytes];
            byte[] randBytes = new byte[32];
            engine.RandomBytes(randBytes, randBytes.Length);
            engine.KemEncrypt(cipherText, sessionKey, key.GetEncoded(), randBytes);
            return new SecretWithEncapsulationImpl(sessionKey, cipherText);
        }

        // FIXME Avoid needing this in the public API
        public ISecretWithEncapsulation InternalGenerateEncapsulated(AsymmetricKeyParameter recipientKey, byte[] randBytes)
        {
            MLKemPublicKeyParameters key = (MLKemPublicKeyParameters)recipientKey;
            MLKemEngine engine = key.Parameters.Engine;
            engine.Init(m_random);
            byte[] cipherText = new byte[engine.CryptoCipherTextBytes];
            byte[] sessionKey = new byte[engine.CryptoBytes];
            engine.KemEncryptInternal(cipherText, sessionKey, key.GetEncoded(), randBytes);
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
                    Arrays.Clear(m_sessionKey);
                    Arrays.Clear(m_cipherText);
                    m_hasBeenDestroyed = true;
                }
                GC.SuppressFinalize(this);
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