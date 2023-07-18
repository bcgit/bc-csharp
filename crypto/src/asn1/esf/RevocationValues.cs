using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
	/// <remarks>
	/// RFC 5126: 6.3.4.  revocation-values Attribute Definition
	/// <code>
	/// RevocationValues ::=  SEQUENCE {
	///		crlVals			[0] SEQUENCE OF CertificateList     OPTIONAL,
	///		ocspVals		[1] SEQUENCE OF BasicOCSPResponse   OPTIONAL,
	///		otherRevVals	[2] OtherRevVals OPTIONAL
	/// }
	/// </code>
	/// </remarks>
	public class RevocationValues
		: Asn1Encodable
	{
		private readonly Asn1Sequence m_crlVals;
		private readonly Asn1Sequence m_ocspVals;
		private readonly OtherRevVals m_otherRevVals;

		public static RevocationValues GetInstance(object obj)
		{
            if (obj == null)
                return null;

            if (obj is RevocationValues revocationValues)
				return revocationValues;

			return new RevocationValues(Asn1Sequence.GetInstance(obj));
		}

		private RevocationValues(Asn1Sequence seq)
		{
			if (seq == null)
				throw new ArgumentNullException(nameof(seq));
			if (seq.Count > 3)
				throw new ArgumentException("Bad sequence size: " + seq.Count, nameof(seq));

			foreach (var element in seq)
			{
				var o = Asn1TaggedObject.GetInstance(element, Asn1Tags.ContextSpecific);
				switch (o.TagNo)
				{
				case 0:
					Asn1Sequence crlValsSeq = (Asn1Sequence)o.GetExplicitBaseObject();

					// Validate
					crlValsSeq.MapElements(CertificateList.GetInstance);

					m_crlVals = crlValsSeq;
					break;
				case 1:
					Asn1Sequence ocspValsSeq = (Asn1Sequence)o.GetExplicitBaseObject();

					// Validate
					ocspValsSeq.MapElements(BasicOcspResponse.GetInstance);

					m_ocspVals = ocspValsSeq;
					break;
				case 2:
					m_otherRevVals = OtherRevVals.GetInstance(o.GetExplicitBaseObject());
					break;
				default:
					throw new ArgumentException("Illegal tag in RevocationValues", nameof(seq));
				}
			}
		}

		public RevocationValues(CertificateList[] crlVals, BasicOcspResponse[] ocspVals, OtherRevVals otherRevVals)
		{
			if (crlVals != null)
			{
				m_crlVals = new DerSequence(crlVals);
			}

			if (ocspVals != null)
			{
				m_ocspVals = new DerSequence(ocspVals);
			}

			m_otherRevVals = otherRevVals;
		}

		public RevocationValues(IEnumerable<CertificateList> crlVals, IEnumerable<BasicOcspResponse> ocspVals,
			OtherRevVals otherRevVals)
		{
			if (crlVals != null)
			{
				m_crlVals = new DerSequence(Asn1EncodableVector.FromEnumerable(crlVals));
			}

			if (ocspVals != null)
			{
				m_ocspVals = new DerSequence(Asn1EncodableVector.FromEnumerable(ocspVals));
			}

			m_otherRevVals = otherRevVals;
		}

		public CertificateList[] GetCrlVals()
		{
			return m_crlVals.MapElements(element => CertificateList.GetInstance(element.ToAsn1Object()));
		}

		public BasicOcspResponse[] GetOcspVals()
		{
            return m_ocspVals.MapElements(element => BasicOcspResponse.GetInstance(element.ToAsn1Object()));
		}

		public OtherRevVals OtherRevVals
		{
			get { return m_otherRevVals; }
		}

		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(true, 0, m_crlVals);
            v.AddOptionalTagged(true, 1, m_ocspVals);

            if (m_otherRevVals != null)
			{
				v.Add(new DerTaggedObject(true, 2, m_otherRevVals.ToAsn1Object()));
			}

            return new DerSequence(v);
		}
	}
}
