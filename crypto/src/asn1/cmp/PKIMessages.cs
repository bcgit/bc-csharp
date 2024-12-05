using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cmp
{
    public class PkiMessages
        : Asn1Encodable
    {
        public static PkiMessages GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiMessages pkiMessages)
                return pkiMessages;
            return new PkiMessages(Asn1Sequence.GetInstance(obj));
        }

        public static PkiMessages GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiMessages(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static PkiMessages GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiMessages(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private Asn1Sequence m_content;

        internal PkiMessages(Asn1Sequence seq)
        {
            m_content = seq;
        }

        internal PkiMessages(PkiMessages other)
        {
            m_content = other.m_content;
        }

        public PkiMessages(params PkiMessage[] msgs)
        {
            m_content = new DerSequence(msgs);
        }

        public virtual PkiMessage[] ToPkiMessageArray() => m_content.MapElements(PkiMessage.GetInstance);

        /**
         * <pre>
         * PkiMessages ::= SEQUENCE SIZE (1..MAX) OF PkiMessage
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
