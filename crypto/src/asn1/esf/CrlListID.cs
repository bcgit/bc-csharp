using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Esf
{
	/// <remarks>
	/// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
	/// <code>
	/// CRLListID ::= SEQUENCE 
	/// {
	///		crls	SEQUENCE OF CrlValidatedID
	/// }
	/// </code>
	/// </remarks>
	public class CrlListID
		: Asn1Encodable
	{
		private readonly Asn1Sequence m_crls;

		public static CrlListID GetInstance(object obj)
		{
			if (obj == null)
				return null;

			if (obj is CrlListID crlListID)
				return crlListID;

			if (obj is Asn1Sequence asn1Sequence)
				return new CrlListID(asn1Sequence);

			throw new ArgumentException("Unknown object in 'CrlListID' factory: " + Platform.GetTypeName(obj),
				nameof(obj));
		}

		private CrlListID(Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException(nameof(seq));
			if (seq.Count != 1)
				throw new ArgumentException("Bad sequence size: " + seq.Count, nameof(seq));

			m_crls = (Asn1Sequence)seq[0].ToAsn1Object();

			// Validate
			m_crls.MapElements(element => CrlValidatedID.GetInstance(element.ToAsn1Object()));
		}

		public CrlListID(params CrlValidatedID[] crls)
		{
			if (crls == null)
				throw new ArgumentNullException(nameof(crls));

			this.m_crls = new DerSequence(crls);
		}

		public CrlListID(IEnumerable<CrlValidatedID> crls)
		{
			if (crls == null)
                throw new ArgumentNullException(nameof(crls));

            this.m_crls = new DerSequence(Asn1EncodableVector.FromEnumerable(crls));
		}

		public CrlValidatedID[] GetCrls()
		{
            return m_crls.MapElements(element => CrlValidatedID.GetInstance(element.ToAsn1Object()));
		}

		public override Asn1Object ToAsn1Object()
		{
			return new DerSequence(m_crls);
		}
	}
}
