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
            return new RecipientKeyIdentifier(Asn1Sequence.GetInstance(obj));
        }

        public static RecipientKeyIdentifier GetInstance(Asn1TaggedObject ato, bool explicitly)
        {
            return new RecipientKeyIdentifier(Asn1Sequence.GetInstance(ato, explicitly));
        }

        private Asn1OctetString      subjectKeyIdentifier;
        private Asn1GeneralizedTime  date;
        private OtherKeyAttribute    other;

		public RecipientKeyIdentifier(
            Asn1OctetString         subjectKeyIdentifier,
            Asn1GeneralizedTime     date,
            OtherKeyAttribute       other)
        {
            this.subjectKeyIdentifier = subjectKeyIdentifier;
            this.date = date;
            this.other = other;
        }
		
		public RecipientKeyIdentifier(
			byte[] subjectKeyIdentifier)
			: this(subjectKeyIdentifier, null, null)
		{
		}

		public RecipientKeyIdentifier(
			byte[]				subjectKeyIdentifier,
            Asn1GeneralizedTime date,
			OtherKeyAttribute	other)
		{
			this.subjectKeyIdentifier = new DerOctetString(subjectKeyIdentifier);
			this.date = date;
			this.other = other;
		}

		public RecipientKeyIdentifier(Asn1Sequence seq)
        {
            subjectKeyIdentifier = Asn1OctetString.GetInstance(seq[0]);

			switch(seq.Count)
            {
			case 1:
				break;
			case 2:
				if (seq[1] is Asn1GeneralizedTime asn1GeneralizedTime)
				{
					date = asn1GeneralizedTime;
				}
				else
				{
					other = OtherKeyAttribute.GetInstance(seq[2]);
				}
				break;
			case 3:
				date = (Asn1GeneralizedTime)seq[1];
				other = OtherKeyAttribute.GetInstance(seq[2]);
				break;
			default:
				throw new ArgumentException("Invalid RecipientKeyIdentifier");
            }
        }

        public Asn1OctetString SubjectKeyIdentifier
		{
			get { return subjectKeyIdentifier; }
		}

		public Asn1GeneralizedTime Date
		{
			get { return date; }
		}

		public OtherKeyAttribute OtherKeyAttribute
		{
			get { return other; }
		}

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
            Asn1EncodableVector v = new Asn1EncodableVector(subjectKeyIdentifier);
			v.AddOptional(date, other);
			return new DerSequence(v);
        }
    }
}
