using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto
{
    public sealed class TlsHybridAgreement
        : TlsAgreement
    {
        private readonly TlsCrypto m_crypto;
        private readonly TlsAgreement m_firstAgreement;
        private readonly TlsAgreement m_secondAgreement;
        private readonly int m_peerValueSplit;

        public TlsHybridAgreement(TlsCrypto crypto, TlsAgreement firstAgreement, TlsAgreement secondAgreement,
            int peerValueSplit)
        {
            m_crypto = crypto ?? throw new ArgumentNullException(nameof(crypto));
            m_firstAgreement = firstAgreement ?? throw new ArgumentNullException(nameof(firstAgreement));
            m_secondAgreement = secondAgreement ?? throw new ArgumentNullException(nameof(secondAgreement));
            m_peerValueSplit = peerValueSplit;
        }

        public byte[] GenerateEphemeral()
        {
            byte[] firstEphemeral = m_firstAgreement.GenerateEphemeral();
            byte[] secondEphemeral = m_secondAgreement.GenerateEphemeral();
            return Arrays.Concatenate(firstEphemeral, secondEphemeral);
        }

        public void ReceivePeerValue(byte[] peerValue)
        {
            if (peerValue.Length < m_peerValueSplit)
                throw new ArgumentException("too short", nameof(peerValue));

            m_firstAgreement.ReceivePeerValue(Arrays.CopyOfRange(peerValue, 0, m_peerValueSplit));
            m_secondAgreement.ReceivePeerValue(Arrays.CopyOfRange(peerValue, m_peerValueSplit, peerValue.Length));
        }

        public TlsSecret CalculateSecret()
        {
            TlsSecret firstSecret = m_firstAgreement.CalculateSecret();
            TlsSecret secondSecret = m_secondAgreement.CalculateSecret();
            return m_crypto.CreateHybridSecret(firstSecret, secondSecret);
        }
    }
}
