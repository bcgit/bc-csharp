using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    public class PkiMessage
        : Asn1Encodable
    {
        public static PkiMessage GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiMessage pkiMessage)
                return pkiMessage;
            return new PkiMessage(Asn1Sequence.GetInstance(obj));
        }

        public static PkiMessage GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiMessage(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static PkiMessage GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiMessage(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly PkiHeader m_header;
        private readonly PkiBody m_body;
        private readonly DerBitString m_protection;
        private readonly Asn1Sequence m_extraCerts;

        private PkiMessage(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_header = PkiHeader.GetInstance(seq[pos++]);
            m_body = PkiBody.GetInstance(seq[pos++]);
            m_protection = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DerBitString.GetTagged);
            m_extraCerts = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, Asn1Sequence.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /**
         * Creates a new PkiMessage.
         *
         * @param header message header
         * @param body message body
         * @param protection message protection (may be null)
         * @param extraCerts extra certificates (may be null)
         */
        public PkiMessage(PkiHeader header, PkiBody body, DerBitString protection, CmpCertificate[] extraCerts)
        {
            m_header = header ?? throw new ArgumentNullException(nameof(header));
            m_body = body ?? throw new ArgumentNullException(nameof(body));
            m_protection = protection;
            m_extraCerts = DerSequence.FromElementsOptional(extraCerts);
        }

        public PkiMessage(PkiHeader header, PkiBody body, DerBitString protection)
            : this(header, body, protection, null)
        {
        }

        public PkiMessage(PkiHeader header, PkiBody body)
            : this(header, body, null, null)
        {
        }

        public virtual PkiHeader Header => m_header;

        public virtual PkiBody Body => m_body;

        public virtual DerBitString Protection => m_protection;

        public virtual CmpCertificate[] GetExtraCerts() => m_extraCerts?.MapElements(CmpCertificate.GetInstance);

        /**
         * <pre>
         * PkiMessage ::= SEQUENCE {
         *                  header           PKIHeader,
         *                  body             PKIBody,
         *                  protection   [0] PKIProtection OPTIONAL,
         *                  extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
         *                                                                     OPTIONAL
         * }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_header, m_body);
            v.AddOptionalTagged(true, 0, m_protection);
            v.AddOptionalTagged(true, 1, m_extraCerts);
            return new DerSequence(v);
        }
    }
}
