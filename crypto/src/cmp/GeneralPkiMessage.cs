using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;

namespace Org.BouncyCastle.Cmp
{
    public class GeneralPkiMessage
    {
        private readonly PkiMessage m_pkiMessage;

        private static PkiMessage ParseBytes(byte[] encoding)
        {
            return PkiMessage.GetInstance(Asn1Object.FromByteArray(encoding));
        }

        /// <summary>
        /// Wrap a PKIMessage ASN.1 structure.
        /// </summary>
        /// <param name="pkiMessage">PKI message.</param>
        public GeneralPkiMessage(PkiMessage pkiMessage)
        {
            this.m_pkiMessage = pkiMessage;
        }

        /// <summary>
        /// Create a PKIMessage from the passed in bytes.
        /// </summary>
        /// <param name="encoding">BER/DER encoding of the PKIMessage</param>
        public GeneralPkiMessage(byte[] encoding)
            : this(ParseBytes(encoding))
        {
        }

        public virtual PkiHeader Header => m_pkiMessage.Header;

        public virtual PkiBody Body => m_pkiMessage.Body;

        /// <summary>
        /// Return true if this message has protection bits on it. A return value of true
        /// indicates the message can be used to construct a ProtectedPKIMessage.
        /// </summary>
        public virtual bool HasProtection => m_pkiMessage.Protection != null;

        public virtual PkiMessage ToAsn1Structure() => m_pkiMessage;
    }
}
