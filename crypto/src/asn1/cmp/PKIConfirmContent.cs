using System;

using Org.BouncyCastle.Utilities;

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

			if (obj is Asn1Null asn1Null)
				return new PkiConfirmContent(asn1Null);

            throw new ArgumentException("Invalid object: " + Platform.GetTypeName(obj), nameof(obj));
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
