namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>GenMsgContent ::= SEQUENCE OF InfoTypeAndValue</pre>
     */
    public class GenMsgContent
		: Asn1Encodable
	{
        public static GenMsgContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is GenMsgContent genMsgContent)
                return genMsgContent;
            return new GenMsgContent(Asn1Sequence.GetInstance(obj));
        }

        public static GenMsgContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1Sequence m_content;

		private GenMsgContent(Asn1Sequence seq)
		{
			m_content = seq;
		}

        public GenMsgContent(InfoTypeAndValue itv)
        {
            m_content = new DerSequence(itv);
        }

        public GenMsgContent(params InfoTypeAndValue[] itvs)
		{
			m_content = new DerSequence(itvs);
		}

		public virtual InfoTypeAndValue[] ToInfoTypeAndValueArray()
		{
			return m_content.MapElements(InfoTypeAndValue.GetInstance);
		}

		/**
		 * <pre>
		 * GenMsgContent ::= SEQUENCE OF InfoTypeAndValue
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			return m_content;
		}
	}
}
