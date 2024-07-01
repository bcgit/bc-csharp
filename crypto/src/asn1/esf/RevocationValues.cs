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
		public static RevocationValues GetInstance(object obj)
		{
            if (obj == null)
                return null;
            if (obj is RevocationValues revocationValues)
				return revocationValues;
			return new RevocationValues(Asn1Sequence.GetInstance(obj));
		}

        public static RevocationValues GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return new RevocationValues(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private readonly Asn1Sequence m_crlVals;
        private readonly Asn1Sequence m_ocspVals;
        private readonly OtherRevVals m_otherRevVals;

        private RevocationValues(Asn1Sequence seq)
		{
			int count = seq.Count;
			if (count < 0 || count > 3)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			int pos = 0;

			m_crlVals = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1Sequence.GetTagged);
            m_crlVals?.MapElements(CertificateList.GetInstance); // Validate

            m_ocspVals = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, Asn1Sequence.GetTagged);
            m_ocspVals?.MapElements(BasicOcspResponse.GetInstance); // Validate

            m_otherRevVals = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, OtherRevVals.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public RevocationValues(CertificateList[] crlVals, BasicOcspResponse[] ocspVals, OtherRevVals otherRevVals)
		{
            m_crlVals = DerSequence.FromElementsOptional(crlVals);
            m_ocspVals = DerSequence.FromElementsOptional(ocspVals);
			m_otherRevVals = otherRevVals;
		}

		public RevocationValues(IEnumerable<CertificateList> crlVals, IEnumerable<BasicOcspResponse> ocspVals,
			OtherRevVals otherRevVals)
		{
			if (crlVals != null)
			{
				m_crlVals = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(crlVals));
			}

			if (ocspVals != null)
			{
				m_ocspVals = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(ocspVals));
			}

			m_otherRevVals = otherRevVals;
		}

		public CertificateList[] GetCrlVals() => m_crlVals?.MapElements(CertificateList.GetInstance);

		public BasicOcspResponse[] GetOcspVals() => m_ocspVals?.MapElements(BasicOcspResponse.GetInstance);

		public OtherRevVals OtherRevVals => m_otherRevVals;

		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(true, 0, m_crlVals);
            v.AddOptionalTagged(true, 1, m_ocspVals);
            v.AddOptionalTagged(true, 2, m_otherRevVals);
            return DerSequence.FromVector(v);
		}
	}
}
