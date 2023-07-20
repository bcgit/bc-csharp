namespace Org.BouncyCastle.Asn1.Cmp
{
	public class PopoDecKeyRespContent
		: Asn1Encodable
	{
        public static PopoDecKeyRespContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PopoDecKeyRespContent popoDecKeyRespContent)
                return popoDecKeyRespContent;
            return new PopoDecKeyRespContent(Asn1Sequence.GetInstance(obj));
        }

        public static PopoDecKeyRespContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new PopoDecKeyRespContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1Sequence m_content;

		private PopoDecKeyRespContent(Asn1Sequence seq)
		{
			m_content = seq;
		}

		public virtual DerInteger[] ToIntegerArray() => m_content.MapElements(DerInteger.GetInstance);

		/**
		 * <pre>
		 * PopoDecKeyRespContent ::= SEQUENCE OF INTEGER
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object() => m_content;
	}
}
