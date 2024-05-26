using System;

using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
    /// <code>
    /// OcspIdentifier ::= SEQUENCE {
    ///		ocspResponderID		ResponderID,
    ///			-- As in OCSP response data
    ///		producedAt			GeneralizedTime
    ///			-- As in OCSP response data
    /// }
    /// </code>
    /// </remarks>
    public class OcspIdentifier
		: Asn1Encodable
	{
		public static OcspIdentifier GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is OcspIdentifier ocspIdentifier)
				return ocspIdentifier;
			return new OcspIdentifier(Asn1Sequence.GetInstance(obj));
		}

        public static OcspIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new OcspIdentifier(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly ResponderID m_ocspResponderID;
        private readonly Asn1GeneralizedTime m_producedAt;

        private OcspIdentifier(Asn1Sequence seq)
		{
			int count = 2;
			if (count != 2)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_ocspResponderID = ResponderID.GetInstance(seq[0]);
			m_producedAt = Asn1GeneralizedTime.GetInstance(seq[1]);
		}

		public OcspIdentifier(ResponderID ocspResponderID, DateTime producedAt)
			: this(ocspResponderID, Rfc5280Asn1Utilities.CreateGeneralizedTime(producedAt))
		{
		}

        public OcspIdentifier(ResponderID ocspResponderID, Asn1GeneralizedTime producedAt)
        {
            m_ocspResponderID = ocspResponderID ?? throw new ArgumentNullException(nameof(ocspResponderID));
            m_producedAt = producedAt ?? throw new ArgumentNullException(nameof(producedAt));
        }

		public ResponderID OcspResponderID => m_ocspResponderID;

		public Asn1GeneralizedTime ProducedAtData => m_producedAt;

		public DateTime ProducedAt => m_producedAt.ToDateTime();

		public override Asn1Object ToAsn1Object() => new DerSequence(m_ocspResponderID, m_producedAt);
	}
}
