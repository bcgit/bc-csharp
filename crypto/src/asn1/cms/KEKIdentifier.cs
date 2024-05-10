using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class KekIdentifier
        : Asn1Encodable
    {
        public static KekIdentifier GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KekIdentifier kekIdentifier)
                return kekIdentifier;
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekIdentifier(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static KekIdentifier GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new KekIdentifier(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private Asn1OctetString		keyIdentifier;
        private Asn1GeneralizedTime date;
        private OtherKeyAttribute	other;

		public KekIdentifier(
            byte[]              keyIdentifier,
            Asn1GeneralizedTime date,
            OtherKeyAttribute   other)
        {
            this.keyIdentifier = new DerOctetString(keyIdentifier);
            this.date = date;
            this.other = other;
        }

        [Obsolete("Use 'GetInstance' instead")]
        public KekIdentifier(Asn1Sequence seq)
        {
            keyIdentifier = (Asn1OctetString)seq[0];

			switch (seq.Count)
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
				throw new ArgumentException("Invalid KekIdentifier");
            }
        }

        public Asn1OctetString KeyIdentifier
		{
			get { return keyIdentifier; }
		}

		public Asn1GeneralizedTime Date
		{
			get { return date; }
		}

		public OtherKeyAttribute Other
		{
			get { return other; }
		}

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * KekIdentifier ::= Sequence {
         *     keyIdentifier OCTET STRING,
         *     date GeneralizedTime OPTIONAL,
         *     other OtherKeyAttribute OPTIONAL
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(keyIdentifier);
			v.AddOptional(date, other);
			return new DerSequence(v);
        }
    }
}

