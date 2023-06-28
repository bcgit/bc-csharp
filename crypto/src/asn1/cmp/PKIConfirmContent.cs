using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     *  PKIConfirmContent ::= NULL
     */
    public class PkiConfirmContent
		: Asn1Encodable
	{
		public static PkiConfirmContent GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is PkiConfirmContent pkiConfirmContent)
				return pkiConfirmContent;
			return new PkiConfirmContent(Asn1Null.GetInstance(obj));
		}

        public static PkiConfirmContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Null.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1Null m_val;

        public PkiConfirmContent()
            : this(DerNull.Instance)
        {
        }

        private PkiConfirmContent(Asn1Null val)
        {
            m_val = val;
        }

		/**
		 * <pre>
		 * PkiConfirmContent ::= NULL
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			return m_val;
		}
	}
}
