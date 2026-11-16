using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The RecipientKeyIdentifier structure of RFC 5652.</summary>
    public class RecipientKeyIdentifier
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="RecipientKeyIdentifier"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="RecipientKeyIdentifier"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="RecipientKeyIdentifier"/>, or null if <paramref name="obj"/> is null.</returns>
        public static RecipientKeyIdentifier GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RecipientKeyIdentifier recipientKeyIdentifier)
                return recipientKeyIdentifier;
#pragma warning disable CS0618 // Type or member is obsolete
            return new RecipientKeyIdentifier(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="RecipientKeyIdentifier"/> from a tagged object.</summary>
        /// <param name="ato">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RecipientKeyIdentifier"/>.</returns>
        public static RecipientKeyIdentifier GetInstance(Asn1TaggedObject ato, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new RecipientKeyIdentifier(Asn1Sequence.GetInstance(ato, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="RecipientKeyIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RecipientKeyIdentifier"/>.</returns>
        public static RecipientKeyIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new RecipientKeyIdentifier(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1OctetString m_subjectKeyIdentifier;
        private readonly Asn1GeneralizedTime m_date;
        private readonly OtherKeyAttribute m_other;

        /// <summary>Create a new <see cref="RecipientKeyIdentifier"/>.</summary>
        /// <param name="subjectKeyIdentifier">The subject key identifier.</param>
        /// <param name="date">The date.</param>
        /// <param name="other">The other.</param>
        public RecipientKeyIdentifier(Asn1OctetString subjectKeyIdentifier, Asn1GeneralizedTime date,
            OtherKeyAttribute other)
        {
            m_subjectKeyIdentifier = subjectKeyIdentifier ?? throw new ArgumentNullException(nameof(subjectKeyIdentifier));
            m_date = date;
            m_other = other;
        }

        /// <summary>Create a new <see cref="RecipientKeyIdentifier"/>.</summary>
        /// <param name="subjectKeyIdentifier">The subject key identifier.</param>
        public RecipientKeyIdentifier(byte[] subjectKeyIdentifier)
            : this(subjectKeyIdentifier, null, null)
        {
        }

        /// <summary>Create a new <see cref="RecipientKeyIdentifier"/>.</summary>
        /// <param name="subjectKeyIdentifier">The subject key identifier.</param>
        /// <param name="date">The date.</param>
        /// <param name="other">The other.</param>
        public RecipientKeyIdentifier(byte[] subjectKeyIdentifier, Asn1GeneralizedTime date, OtherKeyAttribute other)
        {
            m_subjectKeyIdentifier = DerOctetString.FromContents(subjectKeyIdentifier);
            m_date = date;
            m_other = other;
        }

        /// <summary>Create a new <see cref="RecipientKeyIdentifier"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public RecipientKeyIdentifier(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_subjectKeyIdentifier = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_date = Asn1Utilities.ReadOptional(seq, ref pos, Asn1GeneralizedTime.GetOptional);
            m_other = Asn1Utilities.ReadOptional(seq, ref pos, OtherKeyAttribute.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the subject key identifier.</summary>
        public Asn1OctetString SubjectKeyIdentifier => m_subjectKeyIdentifier;

        /// <summary>Gets the date.</summary>
        public Asn1GeneralizedTime Date => m_date;

        /// <summary>Gets the other key attribute.</summary>
        public OtherKeyAttribute OtherKeyAttribute => m_other;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * RecipientKeyIdentifier ::= Sequence {
         *     subjectKeyIdentifier SubjectKeyIdentifier,
         *     date GeneralizedTime OPTIONAL,
         *     other OtherKeyAttribute OPTIONAL
         * }
         *
         * SubjectKeyIdentifier ::= OCTET STRING
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_subjectKeyIdentifier);
            v.AddOptional(m_date, m_other);
            return new DerSequence(v);
        }
    }
}
