using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>
    /// The ProtectedPart structure of RFC 4210: the header and body of a message, which are covered by its protection.
    /// </summary>
    public class ProtectedPart
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="ProtectedPart"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ProtectedPart"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ProtectedPart"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ProtectedPart GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ProtectedPart popoDecKeyRespContent)
                return popoDecKeyRespContent;
            return new ProtectedPart(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ProtectedPart"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ProtectedPart"/>.</returns>
        public static ProtectedPart GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ProtectedPart(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="ProtectedPart"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ProtectedPart"/>.</returns>
        public static ProtectedPart GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ProtectedPart(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly PkiHeader m_header;
        private readonly PkiBody m_body;

        private ProtectedPart(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_header = Asn1Utilities.Read(seq, ref pos, PkiHeader.GetInstance);
            m_body = Asn1Utilities.Read(seq, ref pos, PkiBody.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="ProtectedPart"/>.</summary>
        /// <param name="header">The header.</param>
        /// <param name="body">The body.</param>
        public ProtectedPart(PkiHeader header, PkiBody body)
        {
            m_header = header ?? throw new ArgumentNullException(nameof(header));
            m_body = body ?? throw new ArgumentNullException(nameof(body));
        }

        /// <summary>Gets the header.</summary>
        public virtual PkiHeader Header => m_header;

        /// <summary>Gets the body.</summary>
        public virtual PkiBody Body => m_body;

        /**
         * <pre>
         * ProtectedPart ::= SEQUENCE {
         *                    header    PKIHeader,
         *                    body      PKIBody
         * }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_header, m_body);
    }
}
