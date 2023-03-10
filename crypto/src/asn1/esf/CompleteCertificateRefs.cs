using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Esf
{
	/// <remarks>
	/// RFC 3126: 4.2.1 Complete Certificate Refs Attribute Definition
	/// <code>
	/// CompleteCertificateRefs ::= SEQUENCE OF OtherCertID
	/// </code>
	/// </remarks>
	public class CompleteCertificateRefs
		: Asn1Encodable
	{
		private readonly Asn1Sequence m_otherCertIDs;

		public static CompleteCertificateRefs GetInstance(object obj)
		{
			if (obj == null)
				return null;

            if (obj is CompleteCertificateRefs completeCertificateRefs)
				return completeCertificateRefs;

			if (obj is Asn1Sequence asn1Sequence)
				return new CompleteCertificateRefs(asn1Sequence);

			throw new ArgumentException("Unknown object in 'CompleteCertificateRefs' factory: " + Platform.GetTypeName(obj),
				nameof(obj));
		}

		private CompleteCertificateRefs(Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException(nameof(seq));

            // Validate
            seq.MapElements(element => OtherCertID.GetInstance(element.ToAsn1Object()));

            m_otherCertIDs = seq;
		}

		public CompleteCertificateRefs(params OtherCertID[] otherCertIDs)
		{
			if (otherCertIDs == null)
				throw new ArgumentNullException(nameof(otherCertIDs));

			m_otherCertIDs = new DerSequence(otherCertIDs);
		}

		public CompleteCertificateRefs(IEnumerable<OtherCertID> otherCertIDs)
		{
			if (otherCertIDs == null)
                throw new ArgumentNullException(nameof(otherCertIDs));

            m_otherCertIDs = new DerSequence(Asn1EncodableVector.FromEnumerable(otherCertIDs));
		}

		public OtherCertID[] GetOtherCertIDs()
		{
            return m_otherCertIDs.MapElements(element => OtherCertID.GetInstance(element.ToAsn1Object()));
		}

		public override Asn1Object ToAsn1Object()
		{
			return m_otherCertIDs;
		}
	}
}
