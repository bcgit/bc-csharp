namespace Org.BouncyCastle.Asn1.Cmp
{
    public class GeneralPKIMessage
    {
        private readonly PkiMessage pkiMessage;

        private static PkiMessage parseBytes(byte[] encoding)
        {
            return PkiMessage.GetInstance(Asn1Object.FromByteArray(encoding));
        }


        /// <summary>
        /// Wrap a PKIMessage ASN.1 structure.
        /// </summary>
        /// <param name="pkiMessage">PKI message.</param>
        public GeneralPKIMessage(PkiMessage pkiMessage)
        {
            this.pkiMessage = pkiMessage;
        }

        /// <summary>
        /// Create a PKIMessage from the passed in bytes.
        /// </summary>
        /// <param name="encoding">BER/DER encoding of the PKIMessage</param>
        public GeneralPKIMessage(byte[] encoding) : this(parseBytes(encoding))
        {
        }

        public PkiHeader Header
        {
            get
            {
                return pkiMessage.Header;
            }
        }

        public PkiBody Body
        {
            get
            {
                return pkiMessage.Body;
            }
        }

        /// <summary>
        /// Return true if this message has protection bits on it. A return value of true
        /// indicates the message can be used to construct a ProtectedPKIMessage.
        /// </summary>
        public bool HasProtection
        {
            get { return pkiMessage.Protection != null; }
        }

        public PkiMessage ToAsn1Structure()
        {
            return pkiMessage;
        }
    }
}
