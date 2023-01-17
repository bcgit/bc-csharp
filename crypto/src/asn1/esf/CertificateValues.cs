using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Esf
{
	/// <remarks>
	/// RFC 3126: 4.3.1 Certificate Values Attribute Definition
	/// <code>
	/// CertificateValues ::= SEQUENCE OF Certificate
	/// </code>
	/// </remarks>
	public class CertificateValues
		: Asn1Encodable
	{
		private readonly Asn1Sequence m_certificates;

		public static CertificateValues GetInstance(object obj)
		{
			if (obj == null)
				return null;

			if (obj is CertificateValues certificateValues)
				return certificateValues;

			if (obj is Asn1Sequence asn1Sequence)
				return new CertificateValues(asn1Sequence);

			throw new ArgumentException("Unknown object in 'CertificateValues' factory: " + Platform.GetTypeName(obj),
				nameof(obj));
		}

		private CertificateValues(Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException(nameof(seq));

			// Validate
            seq.MapElements(element => X509CertificateStructure.GetInstance(element.ToAsn1Object()));

			m_certificates = seq;
		}

		public CertificateValues(params X509CertificateStructure[] certificates)
		{
			if (certificates == null)
				throw new ArgumentNullException(nameof(certificates));

			m_certificates = new DerSequence(certificates);
		}

		public CertificateValues(IEnumerable<X509CertificateStructure> certificates)
		{
			if (certificates == null)
                throw new ArgumentNullException(nameof(certificates));

            m_certificates = new DerSequence(Asn1EncodableVector.FromEnumerable(certificates));
		}

		public X509CertificateStructure[] GetCertificates()
		{
			return m_certificates.MapElements(element => X509CertificateStructure.GetInstance(element.ToAsn1Object()));
		}

		public override Asn1Object ToAsn1Object()
		{
			return m_certificates;
		}
 	}
}
