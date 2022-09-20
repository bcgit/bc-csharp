using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class PollReqContent
		: Asn1Encodable
	{
        public static PollReqContent GetInstance(object obj)
        {
			if (obj is PollReqContent pollReqContent)
				return pollReqContent;

			if (obj != null)
				return new PollReqContent(Asn1Sequence.GetInstance(obj));

			return null;
        }

        private readonly Asn1Sequence m_content;

		private PollReqContent(Asn1Sequence seq)
		{
			m_content = seq;
		}

		/**
		 * Create a pollReqContent for a single certReqId.
		 *
		 * @param certReqId the certificate request ID.
		 */
		public PollReqContent(DerInteger certReqId)
			: this(new DerSequence(new DerSequence(certReqId)))
		{
		}

		/**
		 * Create a pollReqContent for a multiple certReqIds.
		 *
		 * @param certReqIds the certificate request IDs.
		 */
		public PollReqContent(DerInteger[] certReqIds)
			: this(new DerSequence(IntsToSequence(certReqIds)))
		{
		}

		/**
		 * Create a pollReqContent for a single certReqId.
		 *
		 * @param certReqId the certificate request ID.
		 */
		public PollReqContent(BigInteger certReqId)
			: this(new DerInteger(certReqId))
		{
		}

		/**
		 * Create a pollReqContent for a multiple certReqIds.
		 *
		 * @param certReqIds the certificate request IDs.
		 */
		public PollReqContent(BigInteger[] certReqIds)
			: this(IntsToAsn1(certReqIds))
		{
		}

		public virtual DerInteger[][] GetCertReqIDs()
		{
			DerInteger[][] result = new DerInteger[m_content.Count][];
			for (int i = 0; i != result.Length; ++i)
			{
				result[i] = SequenceToDerIntegerArray((Asn1Sequence)m_content[i]);
			}
			return result;
		}

        public virtual BigInteger[] GetCertReqIDValues()
        {
            BigInteger[] result = new BigInteger[m_content.Count];

            for (int i = 0; i != result.Length; i++)
            {
                result[i] = DerInteger.GetInstance(Asn1Sequence.GetInstance(m_content[i])[0]).Value;
            }

            return result;
        }

        /**
		 * <pre>
		 * PollReqContent ::= SEQUENCE OF SEQUENCE {
		 *                        certReqId              INTEGER
		 * }
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
        public override Asn1Object ToAsn1Object()
		{
			return m_content;
		}

		private static DerInteger[] SequenceToDerIntegerArray(Asn1Sequence seq)
		{
			return seq.MapElements(DerInteger.GetInstance);
		}

		private static DerSequence[] IntsToSequence(DerInteger[] ids)
		{
			DerSequence[] result = new DerSequence[ids.Length];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = new DerSequence(ids[i]);
			}

			return result;
		}

		private static DerInteger[] IntsToAsn1(BigInteger[] ids)
		{
			DerInteger[] result = new DerInteger[ids.Length];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = new DerInteger(ids[i]);
			}

			return result;
		}
	}
}
