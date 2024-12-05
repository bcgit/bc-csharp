using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class CrlAnnContent
		: Asn1Encodable
	{
        public static CrlAnnContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlAnnContent crlAnnContent)
                return crlAnnContent;
            return new CrlAnnContent(Asn1Sequence.GetInstance(obj));
        }

        public static CrlAnnContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlAnnContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CrlAnnContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlAnnContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

		private CrlAnnContent(Asn1Sequence seq)
		{
			m_content = seq;
		}

        public CrlAnnContent(CertificateList crl)
        {
            m_content = new DerSequence(crl);
        }

        public virtual CertificateList[] ToCertificateListArray() => m_content.MapElements(CertificateList.GetInstance);

		/**
		 * <pre>
		 * CrlAnnContent ::= SEQUENCE OF CertificateList
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object() => m_content;
	}
}
