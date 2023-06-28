using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public abstract class BcTlsSigner
        : TlsSigner
    {
        protected readonly BcTlsCrypto m_crypto;
        protected readonly AsymmetricKeyParameter m_privateKey;

        protected BcTlsSigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey)
        {
            if (crypto == null)
                throw new ArgumentNullException("crypto");
            if (privateKey == null)
                throw new ArgumentNullException("privateKey");
            if (!privateKey.IsPrivate)
                throw new ArgumentException("must be private", "privateKey");

            this.m_crypto = crypto;
            this.m_privateKey = privateKey;
        }

        public virtual byte[] GenerateRawSignature(SignatureAndHashAlgorithm algorithm, byte[] hash)
        {
            throw new NotSupportedException();
        }

        public virtual TlsStreamSigner GetStreamSigner(SignatureAndHashAlgorithm algorithm)
        {
            return null;
        }
    }
}
