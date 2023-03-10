using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Esf
{
	/// <remarks>
	/// <code>
	/// OtherSigningCertificate ::= SEQUENCE {
	/// 	certs		SEQUENCE OF OtherCertID,
	/// 	policies	SEQUENCE OF PolicyInformation OPTIONAL
	/// }
	/// </code>
	/// </remarks>
	public class OtherSigningCertificate
		: Asn1Encodable
	{
		private readonly Asn1Sequence m_certs;
		private readonly Asn1Sequence m_policies;

		public static OtherSigningCertificate GetInstance(object obj)
		{
			if (obj == null)
				return null;

			if (obj is OtherSigningCertificate otherSigningCertificate)
				return otherSigningCertificate;

			if (obj is Asn1Sequence asn1Sequence)
				return new OtherSigningCertificate(asn1Sequence);

			throw new ArgumentException("Unknown object in 'OtherSigningCertificate' factory: " + Platform.GetTypeName(obj),
				nameof(obj));
		}

		private OtherSigningCertificate(Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException(nameof(seq));
			if (seq.Count < 1 || seq.Count > 2)
				throw new ArgumentException("Bad sequence size: " + seq.Count, nameof(seq));

			m_certs = Asn1Sequence.GetInstance(seq[0].ToAsn1Object());

			if (seq.Count > 1)
			{
				m_policies = Asn1Sequence.GetInstance(seq[1].ToAsn1Object());
			}
		}

		public OtherSigningCertificate(params OtherCertID[] certs)
			: this(certs, null)
		{
		}

		public OtherSigningCertificate(OtherCertID[] certs, params PolicyInformation[] policies)
		{
			if (certs == null)
                throw new ArgumentNullException(nameof(certs));

            m_certs = new DerSequence(certs);

			if (policies != null)
			{
				m_policies = new DerSequence(policies);
			}
		}

		public OtherSigningCertificate(IEnumerable<OtherCertID> certs)
			: this(certs, null)
		{
		}

		public OtherSigningCertificate(IEnumerable<OtherCertID> certs, IEnumerable<PolicyInformation> policies)
		{
			if (certs == null)
                throw new ArgumentNullException(nameof(certs));

            m_certs = new DerSequence(Asn1EncodableVector.FromEnumerable(certs));

			if (policies != null)
			{
				m_policies = new DerSequence(Asn1EncodableVector.FromEnumerable(policies));
			}
		}

		public OtherCertID[] GetCerts()
		{
			return m_certs.MapElements(element => OtherCertID.GetInstance(element.ToAsn1Object()));
		}

		public PolicyInformation[] GetPolicies()
		{
            return m_policies?.MapElements(element => PolicyInformation.GetInstance(element.ToAsn1Object()));
		}

		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(m_certs);
            v.AddOptional(m_policies);
			return new DerSequence(v);
		}
	}
}
