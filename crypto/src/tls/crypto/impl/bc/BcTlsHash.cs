using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    internal sealed class BcTlsHash
        : TlsHash
    {
        private readonly BcTlsCrypto m_crypto;
        private readonly int m_cryptoHashAlgorithm;
        private readonly IDigest m_digest;

        internal BcTlsHash(BcTlsCrypto crypto, int cryptoHashAlgorithm)
            : this(crypto, cryptoHashAlgorithm, crypto.CreateDigest(cryptoHashAlgorithm))
        {
        }

        private BcTlsHash(BcTlsCrypto crypto, int cryptoHashAlgorithm, IDigest digest)
        {
            this.m_crypto = crypto;
            this.m_cryptoHashAlgorithm = cryptoHashAlgorithm;
            this.m_digest = digest;
        }

        public void Update(byte[] data, int offSet, int length)
        {
            m_digest.BlockUpdate(data, offSet, length);
        }

        public byte[] CalculateHash()
        {
            byte[] rv = new byte[m_digest.GetDigestSize()];
            m_digest.DoFinal(rv, 0);
            return rv;
        }

        public TlsHash CloneHash()
        {
            IDigest clone = m_crypto.CloneDigest(m_cryptoHashAlgorithm, m_digest);
            return new BcTlsHash(m_crypto, m_cryptoHashAlgorithm, clone);
        }

        public void Reset()
        {
            m_digest.Reset();
        }
    }
}
