using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Esf
{
	/// <remarks>
	/// RFC 3126: 4.2.2 Complete Revocation Refs Attribute Definition
	/// <code>
	/// CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
	/// </code>
	/// </remarks>
	public class CompleteRevocationRefs
		: Asn1Encodable
	{
		private readonly Asn1Sequence m_crlOcspRefs;

		public static CompleteRevocationRefs GetInstance(object obj)
		{
			if (obj == null)
				return null;

			if (obj is CompleteRevocationRefs completeRevocationRefs)
				return completeRevocationRefs;

			if (obj is Asn1Sequence asn1Sequence)
				return new CompleteRevocationRefs(asn1Sequence);

			throw new ArgumentException("Unknown object in 'CompleteRevocationRefs' factory: " + Platform.GetTypeName(obj),
				nameof(obj));
		}

		private CompleteRevocationRefs(Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException(nameof(seq));

            // Validate
            seq.MapElements(element => CrlOcspRef.GetInstance(element.ToAsn1Object()));

			m_crlOcspRefs = seq;
		}

		public CompleteRevocationRefs(params CrlOcspRef[] crlOcspRefs)
		{
			if (crlOcspRefs == null)
				throw new ArgumentNullException(nameof(crlOcspRefs));

			m_crlOcspRefs = new DerSequence(crlOcspRefs);
		}

		public CompleteRevocationRefs(IEnumerable<CrlOcspRef> crlOcspRefs)
		{
			if (crlOcspRefs == null)
                throw new ArgumentNullException(nameof(crlOcspRefs));

            m_crlOcspRefs = new DerSequence(Asn1EncodableVector.FromEnumerable(crlOcspRefs));
		}

		public CrlOcspRef[] GetCrlOcspRefs()
		{
            return m_crlOcspRefs.MapElements(element => CrlOcspRef.GetInstance(element.ToAsn1Object()));
		}

		public override Asn1Object ToAsn1Object()
		{
			return m_crlOcspRefs;
		}
	}
}
