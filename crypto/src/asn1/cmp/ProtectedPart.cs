namespace Org.BouncyCastle.Asn1.Cmp
{
	public class ProtectedPart
		: Asn1Encodable
	{
        public static ProtectedPart GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ProtectedPart popoDecKeyRespContent)
                return popoDecKeyRespContent;
            return new ProtectedPart(Asn1Sequence.GetInstance(obj));
        }

        public static ProtectedPart GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new ProtectedPart(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly PkiHeader m_header;
		private readonly PkiBody m_body;

		private ProtectedPart(Asn1Sequence seq)
		{
			m_header = PkiHeader.GetInstance(seq[0]);
			m_body = PkiBody.GetInstance(seq[1]);
		}

		public ProtectedPart(PkiHeader header, PkiBody body)
		{
			m_header = header;
			m_body = body;
		}

		public virtual PkiHeader Header => m_header;

		public virtual PkiBody Body => m_body;

		/**
		 * <pre>
		 * ProtectedPart ::= SEQUENCE {
		 *                    header    PKIHeader,
		 *                    body      PKIBody
		 * }
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object() => new DerSequence(m_header, m_body);
	}
}
