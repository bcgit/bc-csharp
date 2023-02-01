namespace Org.BouncyCastle.Asn1.Cmp
{
	public class RevReqContent
		: Asn1Encodable
	{
        public static RevReqContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RevReqContent revReqContent)
                return revReqContent;
            return new RevReqContent(Asn1Sequence.GetInstance(obj));
        }

        public static RevReqContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1Sequence m_content;

		private RevReqContent(Asn1Sequence seq)
		{
			m_content = seq;
		}

        public RevReqContent(RevDetails revDetails)
        {
            m_content = new DerSequence(revDetails);
        }

        public RevReqContent(params RevDetails[] revDetailsArray)
		{
			m_content = new DerSequence(revDetailsArray);
		}

		public virtual RevDetails[] ToRevDetailsArray()
		{
			return m_content.MapElements(RevDetails.GetInstance);
		}

		/**
		 * <pre>
		 * RevReqContent ::= SEQUENCE OF RevDetails
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			return m_content;
		}
	}
}
