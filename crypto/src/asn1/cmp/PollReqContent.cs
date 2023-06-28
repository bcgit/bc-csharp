using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class PollReqContent
		: Asn1Encodable
	{
        public static PollReqContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PollReqContent pollReqContent)
                return pollReqContent;
            return new PollReqContent(Asn1Sequence.GetInstance(obj));
        }

        public static PollReqContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
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
            return m_content.MapElements(
				element => Asn1Sequence.GetInstance(element).MapElements(DerInteger.GetInstance));
		}

        public virtual BigInteger[] GetCertReqIDValues()
        {
			return m_content.MapElements(element => DerInteger.GetInstance(Asn1Sequence.GetInstance(element)[0]).Value);
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
