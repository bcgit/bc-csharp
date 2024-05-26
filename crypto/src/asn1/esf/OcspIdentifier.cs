using System;

using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

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
		private readonly ResponderID		ocspResponderID;
		private readonly Asn1GeneralizedTime producedAt;

		public static OcspIdentifier GetInstance(
			object obj)
		{
			if (obj == null || obj is OcspIdentifier)
				return (OcspIdentifier) obj;

			if (obj is Asn1Sequence)
				return new OcspIdentifier((Asn1Sequence) obj);

			throw new ArgumentException(
				"Unknown object in 'OcspIdentifier' factory: "
                    + Platform.GetTypeName(obj),
				"obj");
		}

		private OcspIdentifier(
			Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException("seq");
			if (seq.Count != 2)
				throw new ArgumentException("Bad sequence size: " + seq.Count, "seq");

			this.ocspResponderID = ResponderID.GetInstance(seq[0].ToAsn1Object());
			this.producedAt = (Asn1GeneralizedTime)seq[1].ToAsn1Object();
		}

		public OcspIdentifier(ResponderID ocspResponderID, DateTime producedAt)
			: this(ocspResponderID, Rfc5280Asn1Utilities.CreateGeneralizedTime(producedAt))
		{
		}

        public OcspIdentifier(ResponderID ocspResponderID, Asn1GeneralizedTime producedAt)
        {
            if (ocspResponderID == null)
                throw new ArgumentNullException(nameof(ocspResponderID));
            if (producedAt == null)
                throw new ArgumentNullException(nameof(producedAt));

            this.ocspResponderID = ocspResponderID;
            this.producedAt = producedAt;
        }

        public ResponderID OcspResponderID
		{
			get { return ocspResponderID; }
		}

		public DateTime ProducedAt
		{
			get { return producedAt.ToDateTime(); }
		}

		public override Asn1Object ToAsn1Object()
		{
			return new DerSequence(ocspResponderID, producedAt);
		}
	}
}
