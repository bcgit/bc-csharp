namespace Org.BouncyCastle.Asn1.Cmp
{
	public class GenRepContent
		: Asn1Encodable
	{
        public static GenRepContent GetInstance(object obj)
        {
            if (obj is GenRepContent genRepContent)
                return genRepContent;

            if (obj != null)
                return new GenRepContent(Asn1Sequence.GetInstance(obj));

            return null;
        }

        private readonly Asn1Sequence m_content;

		private GenRepContent(Asn1Sequence seq)
		{
			m_content = seq;
		}

        public GenRepContent(InfoTypeAndValue itv)
        {
            m_content = new DerSequence(itv);
        }

        public GenRepContent(params InfoTypeAndValue[] itvs)
		{
			m_content = new DerSequence(itvs);
		}

		public virtual InfoTypeAndValue[] ToInfoTypeAndValueArray()
		{
            return m_content.MapElements(InfoTypeAndValue.GetInstance);
		}

		/**
		 * <pre>
		 * GenRepContent ::= SEQUENCE OF InfoTypeAndValue
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			return m_content;
		}
	}
}
