using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class RecipientKeyIdentifier
        : Asn1Encodable
    {
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

        public static RecipientKeyIdentifier GetInstance(Asn1TaggedObject ato, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new RecipientKeyIdentifier(Asn1Sequence.GetInstance(ato, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static RecipientKeyIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new RecipientKeyIdentifier(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1OctetString m_subjectKeyIdentifier;
        private readonly Asn1GeneralizedTime m_date;
        private readonly OtherKeyAttribute m_other;

        public RecipientKeyIdentifier(Asn1OctetString subjectKeyIdentifier, Asn1GeneralizedTime date,
            OtherKeyAttribute other)
        {
            m_subjectKeyIdentifier = subjectKeyIdentifier ?? throw new ArgumentNullException(nameof(subjectKeyIdentifier));
            m_date = date;
            m_other = other;
        }

        public RecipientKeyIdentifier(byte[] subjectKeyIdentifier)
			: this(subjectKeyIdentifier, null, null)
		{
		}

		public RecipientKeyIdentifier(byte[] subjectKeyIdentifier, Asn1GeneralizedTime date, OtherKeyAttribute other)
		{
			m_subjectKeyIdentifier = new DerOctetString(subjectKeyIdentifier);
			m_date = date;
			m_other = other;
		}

        [Obsolete("Use 'GetInstance' instead")]
        public RecipientKeyIdentifier(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_subjectKeyIdentifier = Asn1OctetString.GetInstance(seq[pos++]);
            m_date = Asn1Utilities.ReadOptional(seq, ref pos, Asn1GeneralizedTime.GetOptional);
            m_other = Asn1Utilities.ReadOptional(seq, ref pos, OtherKeyAttribute.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Asn1OctetString SubjectKeyIdentifier => m_subjectKeyIdentifier;

		public Asn1GeneralizedTime Date => m_date;

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
