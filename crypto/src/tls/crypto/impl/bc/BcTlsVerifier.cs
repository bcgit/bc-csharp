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
                throw new ArgumentNullException("crypto");
            if (publicKey == null)
                throw new ArgumentNullException("publicKey");
            if (publicKey.IsPrivate)
                throw new ArgumentException("must be public", "publicKey");

            this.m_crypto = crypto;
            this.m_publicKey = publicKey;
        }

        public virtual TlsStreamVerifier GetStreamVerifier(DigitallySigned signature)
        {
            return null;
        }

        public abstract bool VerifyRawSignature(DigitallySigned signature, byte[] hash);
    }
}
