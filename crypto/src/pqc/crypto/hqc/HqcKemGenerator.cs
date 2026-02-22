using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    // TODO[api] Make sealed
    public class HqcKemGenerator
        : IEncapsulatedSecretGenerator
    {
        private readonly SecureRandom m_random;

        public HqcKemGenerator(SecureRandom random)
        {
            m_random = CryptoServicesRegistrar.GetSecureRandom(random);
        }

        public ISecretWithEncapsulation GenerateEncapsulated(AsymmetricKeyParameter recipientKey)
        {
            var key = (HqcPublicKeyParameters)recipientKey;
            var parameters = key.Parameters;
            var engine = parameters.Engine;

            byte[] K = new byte[parameters.Sha512Bytes];
            byte[] u = new byte[parameters.NBytes];
            byte[] v = new byte[parameters.N1N2Bytes];
            byte[] salt = new byte[parameters.SaltSizeBytes];
            byte[] pk = key.InternalPublicKey;

            engine.Encaps(u, v, K, pk, salt, m_random);

            byte[] cipherText = Arrays.ConcatenateAll(u, v, salt);

            return new SecretWithEncapsulationImpl(Arrays.CopySegment(K, 0, 32), cipherText);
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
