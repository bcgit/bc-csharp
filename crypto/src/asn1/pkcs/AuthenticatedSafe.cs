namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class AuthenticatedSafe
        : Asn1Encodable
    {
        public static AuthenticatedSafe GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AuthenticatedSafe authenticatedSafe)
                return authenticatedSafe;
            return new AuthenticatedSafe(Asn1Sequence.GetInstance(obj));
        }

        public static AuthenticatedSafe GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AuthenticatedSafe(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static AuthenticatedSafe GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AuthenticatedSafe(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly ContentInfo[] m_info;
        private readonly bool m_isBer;

		private AuthenticatedSafe(Asn1Sequence seq)
        {
            m_info = seq.MapElements(ContentInfo.GetInstance);
            m_isBer = seq is BerSequence;
        }

		public AuthenticatedSafe(ContentInfo[] info)
        {
            m_info = Copy(info);
            m_isBer = true;
        }

        public ContentInfo[] GetContentInfo() => Copy(m_info);

        public override Asn1Object ToAsn1Object()
        {
            return m_isBer
                ?  new BerSequence(m_info)
                :  new DLSequence(m_info);
        }

        private static ContentInfo[] Copy(ContentInfo[] info) => (ContentInfo[])info.Clone();
    }
}
