using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Esf
{
	/// <remarks>
	/// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
	/// <code>
	/// OcspListID ::=  SEQUENCE {
	///		ocspResponses	SEQUENCE OF OcspResponsesID
	/// }
	/// </code>
	/// </remarks>
	public class OcspListID
		: Asn1Encodable
	{
		private readonly Asn1Sequence m_ocspResponses;

		public static OcspListID GetInstance(object obj)
		{
			if (obj == null)
				return null;

			if (obj is OcspListID ocspListID)
				return ocspListID;

			if (obj is Asn1Sequence asn1Sequence)
				return new OcspListID(asn1Sequence);

			throw new ArgumentException("Unknown object in 'OcspListID' factory: " + Platform.GetTypeName(obj),
				nameof(obj));
		}

		private OcspListID(Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException(nameof(seq));
			if (seq.Count != 1)
				throw new ArgumentException("Bad sequence size: " + seq.Count, nameof(seq));

			m_ocspResponses = (Asn1Sequence)seq[0].ToAsn1Object();

            // Validate
            m_ocspResponses.MapElements(element => OcspResponsesID.GetInstance(element.ToAsn1Object()));
		}

		public OcspListID(params OcspResponsesID[] ocspResponses)
		{
			if (ocspResponses == null)
				throw new ArgumentNullException(nameof(ocspResponses));

			m_ocspResponses = new DerSequence(ocspResponses);
		}

		public OcspListID(IEnumerable<OcspResponsesID> ocspResponses)
		{
			if (ocspResponses == null)
                throw new ArgumentNullException(nameof(ocspResponses));

            m_ocspResponses = new DerSequence(Asn1EncodableVector.FromEnumerable(ocspResponses));
		}

		public OcspResponsesID[] GetOcspResponses()
		{
            return m_ocspResponses.MapElements(element => OcspResponsesID.GetInstance(element.ToAsn1Object()));
		}

		public override Asn1Object ToAsn1Object()
		{
			return new DerSequence(m_ocspResponses);
		}
	}
}
