using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.X509;

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
		public static OtherSigningCertificate GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is OtherSigningCertificate otherSigningCertificate)
				return otherSigningCertificate;
			return new OtherSigningCertificate(Asn1Sequence.GetInstance(obj));
		}

        public static OtherSigningCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new OtherSigningCertificate(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1Sequence m_certs;
        private readonly Asn1Sequence m_policies;

        private OtherSigningCertificate(Asn1Sequence seq)
		{
			int count = seq.Count;
			if (count < 1 || count > 2)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_certs = Asn1Sequence.GetInstance(seq[0]);

			if (count > 1)
			{
				m_policies = Asn1Sequence.GetInstance(seq[1]);
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

            m_certs = DerSequence.FromElements(certs);

			if (policies != null)
			{
				m_policies = DerSequence.FromElements(policies);
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

            m_certs = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(certs));

			if (policies != null)
			{
				m_policies = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(policies));
			}
		}

		public OtherCertID[] GetCerts() => m_certs.MapElements(OtherCertID.GetInstance);

		public PolicyInformation[] GetPolicies() => m_policies?.MapElements(PolicyInformation.GetInstance);

		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(2);
			v.Add(m_certs);
            v.AddOptional(m_policies);
			return new DerSequence(v);
		}
	}
}
