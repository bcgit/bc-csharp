using System;

using Org.BouncyCastle.Math.EC.Rfc7748;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    /// <summary>Support class for X448 using the BC light-weight library.</summary>
    public class BcX448
        : TlsAgreement
    {
        protected readonly BcTlsCrypto m_crypto;
        protected readonly byte[] m_privateKey = new byte[X448.ScalarSize];
        protected readonly byte[] m_peerPublicKey = new byte[X448.PointSize];

        public BcX448(BcTlsCrypto crypto)
        {
            this.m_crypto = crypto;
        }

        public virtual byte[] GenerateEphemeral()
        {
            m_crypto.SecureRandom.NextBytes(m_privateKey);

            byte[] publicKey = new byte[X448.PointSize];
            X448.ScalarMultBase(m_privateKey, 0, publicKey, 0);
            return publicKey;
        }

        public virtual void ReceivePeerValue(byte[] peerValue)
        {
            if (peerValue == null || peerValue.Length != X448.PointSize)
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            Array.Copy(peerValue, 0, m_peerPublicKey, 0, X448.PointSize);
        }

        public virtual TlsSecret CalculateSecret()
        {
            try
            {
                byte[] secret = new byte[X448.PointSize];
                if (!X448.CalculateAgreement(m_privateKey, 0, m_peerPublicKey, 0, secret, 0))
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);

                return m_crypto.AdoptLocalSecret(secret);
            }
            finally
            {
                Array.Clear(m_privateKey, 0, m_privateKey.Length);
                Array.Clear(m_peerPublicKey, 0, m_peerPublicKey.Length);
            }
        }
    }
}
