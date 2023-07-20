namespace Org.BouncyCastle.Asn1.Cms
{
    public class TimeStampAndCrl
		: Asn1Encodable
	{
        public static TimeStampAndCrl GetInstance(object obj)
        {
			if (obj == null)
				return null;
            if (obj is TimeStampAndCrl timeStampAndCrl)
                return timeStampAndCrl;
            return new TimeStampAndCrl(Asn1Sequence.GetInstance(obj));
        }

        public static TimeStampAndCrl GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new TimeStampAndCrl(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private ContentInfo timeStamp;
		private X509.CertificateList crl;

		public TimeStampAndCrl(ContentInfo timeStamp)
		{
			this.timeStamp = timeStamp;
		}

		private TimeStampAndCrl(Asn1Sequence seq)
		{
			this.timeStamp = ContentInfo.GetInstance(seq[0]);
			if (seq.Count == 2)
			{
				this.crl = X509.CertificateList.GetInstance(seq[1]);
			}
		}

		public virtual ContentInfo TimeStampToken
		{
			get { return this.timeStamp; }
		}

		public virtual X509.CertificateList Crl
		{
			get { return this.crl; }
		}

		/**
		 * <pre>
		 * TimeStampAndCRL ::= SEQUENCE {
		 *     timeStamp   TimeStampToken,          -- according to RFC 3161
		 *     crl         CertificateList OPTIONAL -- according to RFC 5280
		 *  }
		 * </pre>
		 * @return
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(timeStamp);
			v.AddOptional(crl);
			return new DerSequence(v);
		}
	}
}
