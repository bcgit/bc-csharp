namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * PollRepContent ::= SEQUENCE OF SEQUENCE {
     * certReqId    INTEGER,
     * checkAfter   INTEGER,  -- time in seconds
     * reason       PKIFreeText OPTIONAL }
     */
    public class PollRepContent
		: Asn1Encodable
	{
        public static PollRepContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PollRepContent pollRepContent)
                return pollRepContent;
            return new PollRepContent(Asn1Sequence.GetInstance(obj));
        }

        public static PollRepContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new PollRepContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerInteger[] m_certReqID;
		private readonly DerInteger[] m_checkAfter;
		private readonly PkiFreeText[] m_reason;

		private PollRepContent(Asn1Sequence seq)
		{
			int count = seq.Count;
			m_certReqID = new DerInteger[count];
			m_checkAfter = new DerInteger[count];
			m_reason = new PkiFreeText[count];

			for (int i = 0; i != count; i++)
			{
				Asn1Sequence s = Asn1Sequence.GetInstance(seq[i]);

				m_certReqID[i] = DerInteger.GetInstance(s[0]);
				m_checkAfter[i] = DerInteger.GetInstance(s[1]);

				if (s.Count > 2)
				{
					m_reason[i] = PkiFreeText.GetInstance(s[2]);
				}
			}
		}

	    public PollRepContent(DerInteger certReqID, DerInteger checkAfter)
			: this(certReqID, checkAfter, null)
	    {
	    }

        public PollRepContent(DerInteger certReqID, DerInteger checkAfter, PkiFreeText reason)
	    {
            m_certReqID = new DerInteger[1]{ certReqID };
            m_checkAfter = new DerInteger[1]{ checkAfter };
            m_reason = new PkiFreeText[1]{ reason };
        }

        public virtual int Count => m_certReqID.Length;

        public virtual DerInteger GetCertReqID(int index) => m_certReqID[index];

		public virtual DerInteger GetCheckAfter(int index) => m_checkAfter[index];

		public virtual PkiFreeText GetReason(int index) => m_reason[index];

		/**
		 * <pre>
		 * PollRepContent ::= SEQUENCE OF SEQUENCE {
		 *         certReqId              INTEGER,
		 *         checkAfter             INTEGER,  -- time in seconds
		 *         reason                 PKIFreeText OPTIONAL
		 *     }
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector outer = new Asn1EncodableVector(m_certReqID.Length);

			for (int i = 0; i != m_certReqID.Length; i++)
			{
				Asn1EncodableVector v = new Asn1EncodableVector(3);

				v.Add(m_certReqID[i]);
				v.Add(m_checkAfter[i]);
				v.AddOptional(m_reason[i]);

				outer.Add(new DerSequence(v));
			}

			return new DerSequence(outer);
		}
	}
}
