using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class CrlID
        : Asn1Encodable
    {
        private readonly DerIA5String		crlUrl;
        private readonly DerInteger			crlNum;
        private readonly Asn1GeneralizedTime crlTime;

        public static CrlID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        public static CrlID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlID crlID)
                return crlID;
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlID(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        [Obsolete("Use 'GetInstance' instead")]
        public CrlID(Asn1Sequence seq)
        {
			foreach (Asn1TaggedObject o in seq)
			{
				switch (o.TagNo)
                {
                case 0:
                    crlUrl = DerIA5String.GetInstance(o, true);
                    break;
                case 1:
                    crlNum = DerInteger.GetInstance(o, true);
                    break;
                case 2:
                    crlTime = Asn1GeneralizedTime.GetInstance(o, true);
                    break;
                default:
                    throw new ArgumentException("unknown tag number: " + o.TagNo);
                }
            }
        }

		public DerIA5String CrlUrl
		{
			get { return crlUrl; }
		}

		public DerInteger CrlNum
		{
			get { return crlNum; }
		}

		public Asn1GeneralizedTime CrlTime
		{
			get { return crlTime; }
		}

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * CrlID ::= Sequence {
         *     crlUrl               [0]     EXPLICIT IA5String OPTIONAL,
         *     crlNum               [1]     EXPLICIT Integer OPTIONAL,
         *     crlTime              [2]     EXPLICIT GeneralizedTime OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();
            v.AddOptionalTagged(true, 0, crlUrl);
            v.AddOptionalTagged(true, 1, crlNum);
            v.AddOptionalTagged(true, 2, crlTime);
            return new DerSequence(v);
        }
    }
}
