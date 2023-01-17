using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cmp
{
    public class PkiMessages
        : Asn1Encodable
    {
        private Asn1Sequence m_content;

        internal PkiMessages(Asn1Sequence seq)
        {
            m_content = seq;
        }

        public static PkiMessages GetInstance(object obj)
        {
            if (obj is PkiMessages pkiMessages)
                return pkiMessages;

            if (obj is Asn1Sequence asn1Sequence)
                return new PkiMessages(asn1Sequence);

            throw new ArgumentException("Invalid object: " + Platform.GetTypeName(obj), nameof(obj));
        }

		public PkiMessages(params PkiMessage[] msgs)
        {
            m_content = new DerSequence(msgs);
        }

        public virtual PkiMessage[] ToPkiMessageArray()
        {
            return m_content.MapElements(PkiMessage.GetInstance);
        }

        /**
         * <pre>
         * PkiMessages ::= SEQUENCE SIZE (1..MAX) OF PkiMessage
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_content;
        }
    }
}
