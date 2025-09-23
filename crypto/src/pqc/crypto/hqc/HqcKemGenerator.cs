using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public class HqcKemGenerator
        : IEncapsulatedSecretGenerator
    {
        private readonly SecureRandom m_random;

        public HqcKemGenerator(SecureRandom random)
        {
            m_random = random ?? throw new ArgumentNullException(nameof(random));
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            HqcPublicKeyParameters key = (HqcPublicKeyParameters)recipientKey;
            HqcEngine engine = key.Parameters.Engine;

            byte[] K = new byte[key.Parameters.Sha512Bytes];
            byte[] u = new byte[key.Parameters.NBytes];
            byte[] v = new byte[key.Parameters.N1n2Bytes];
            byte[] salt = new byte[key.Parameters.SaltSizeBytes];
            byte[] seed = SecureRandom.GetNextBytes(m_random, 48);

            engine.Encaps(u, v, K, key.InternalPublicKey, seed, salt);

            byte[] cipherText = Arrays.ConcatenateAll(u, v, salt);

            return new SecretWithEncapsulationImpl(K, cipherText);
        }

        private sealed class SecretWithEncapsulationImpl
            : ISecretWithEncapsulation
        {
            private volatile bool m_hasBeenDestroyed;

            private readonly byte[] m_sessionKey;
            private readonly byte[] m_cipherText;

            internal SecretWithEncapsulationImpl(byte[] sessionKey, byte[] cipherText)
            {
                m_sessionKey = sessionKey;
                m_cipherText = cipherText;
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

            public bool IsDestroyed() => m_hasBeenDestroyed;

            private void CheckDestroyed()
            {
                if (IsDestroyed())
                    throw new Exception("data has been destroyed");
            }
        }
    }
}
