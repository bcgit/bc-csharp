using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>
    /// The PKIMessage structure of RFC 4210: a header, a body, and optionally protection and extra certificates.
    /// </summary>
    public class PkiMessage
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PkiMessage"/> from the given object.</summary>
        /// <param name="obj">An <see cref="PkiMessage"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="PkiMessage"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PkiMessage GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PkiMessage pkiMessage)
                return pkiMessage;
            return new PkiMessage(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PkiMessage"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiMessage"/>.</returns>
        public static PkiMessage GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PkiMessage(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PkiMessage"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PkiMessage"/>.</returns>
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

            m_header = Asn1Utilities.Read(seq, ref pos, PkiHeader.GetInstance);
            m_body = Asn1Utilities.Read(seq, ref pos, PkiBody.GetInstance);
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

        /// <summary>Create a new <see cref="PkiMessage"/>.</summary>
        /// <param name="header">The header.</param>
        /// <param name="body">The body.</param>
        /// <param name="protection">The protection.</param>
        public PkiMessage(PkiHeader header, PkiBody body, DerBitString protection)
            : this(header, body, protection, null)
        {
        }

        /// <summary>Create a new <see cref="PkiMessage"/>.</summary>
        /// <param name="header">The header.</param>
        /// <param name="body">The body.</param>
        public PkiMessage(PkiHeader header, PkiBody body)
            : this(header, body, null, null)
        {
        }

        /// <summary>Gets the header.</summary>
        public virtual PkiHeader Header => m_header;

        /// <summary>Gets the body.</summary>
        public virtual PkiBody Body => m_body;

        /// <summary>Gets the protection.</summary>
        public virtual DerBitString Protection => m_protection;

        /// <summary>Return the extra certs.</summary>
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
