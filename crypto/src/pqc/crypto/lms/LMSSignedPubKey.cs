using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
    public class LmsSignedPubKey
        : IEncodable
    {
        private readonly LmsSignature m_signature;
        private readonly LmsPublicKeyParameters m_publicKey;

        public LmsSignedPubKey(LmsSignature signature, LmsPublicKeyParameters publicKey)
        {
            m_signature = signature;
            m_publicKey = publicKey;
        }

        [Obsolete("Use 'PublicKey' instead")]
        public LmsPublicKeyParameters GetPublicKey() => m_publicKey;

        [Obsolete("Use 'Signature' instead")]
        public LmsSignature GetSignature() => m_signature;

        public LmsPublicKeyParameters PublicKey => m_publicKey;

        public LmsSignature Signature => m_signature;

        public override bool Equals(object obj)
        {
            if (this == obj)
                return true;

            return obj is LmsSignedPubKey that
                && Objects.Equals(this.m_signature, that.m_signature)
                && Objects.Equals(this.m_publicKey, that.m_publicKey);
        }

        public override int GetHashCode()
        {
            int result = Objects.GetHashCode(m_signature);
            result = 31 * result + Objects.GetHashCode(m_publicKey);
            return result;
        }

        public byte[] GetEncoded()
        {
            return Composer.Compose()
                .Bytes(m_signature.GetEncoded())
                .Bytes(m_publicKey.GetEncoded())
                .Build();
        }
    }
}
