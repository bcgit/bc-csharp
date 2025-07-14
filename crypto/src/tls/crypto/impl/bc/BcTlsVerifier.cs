using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Tls.Crypto.Impl.BC
{
    public abstract class BcTlsVerifier
        : TlsVerifier
    {
        protected readonly BcTlsCrypto m_crypto;
        protected readonly AsymmetricKeyParameter m_publicKey;

        protected BcTlsVerifier(BcTlsCrypto crypto, AsymmetricKeyParameter publicKey)
        {
            if (crypto == null)
                throw new ArgumentNullException(nameof(crypto));
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.IsPrivate)
                throw new ArgumentException("must be public", nameof(publicKey));

            m_crypto = crypto;
            m_publicKey = publicKey;
        }

        public virtual TlsStreamVerifier GetStreamVerifier(DigitallySigned digitallySigned) => null;

        public virtual bool VerifyRawSignature(DigitallySigned digitallySigned, byte[] hash) =>
            throw new NotSupportedException();
    }
}
