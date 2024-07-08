using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class CertRepMessage
		: Asn1Encodable
	{
        public static CertRepMessage GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertRepMessage certRepMessage)
                return certRepMessage;
            return new CertRepMessage(Asn1Sequence.GetInstance(obj));
        }

        public static CertRepMessage GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertRepMessage(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CertRepMessage GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertRepMessage(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_caPubs;
		private readonly Asn1Sequence m_response;
		
		private CertRepMessage(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_caPubs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, Asn1Sequence.GetTagged);
			m_response = Asn1Sequence.GetInstance(seq[pos++]);

			if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

		public CertRepMessage(CmpCertificate[] caPubs, CertResponse[] response)
		{
			if (response == null)
				throw new ArgumentNullException(nameof(response));

			if (caPubs != null && caPubs.Length > 0)
			{
				m_caPubs = new DerSequence(caPubs);
			}

			m_response = new DerSequence(response);
		}

		public virtual CmpCertificate[] GetCAPubs() => m_caPubs?.MapElements(CmpCertificate.GetInstance);

		public virtual CertResponse[] GetResponse() => m_response.MapElements(CertResponse.GetInstance);

		/**
		 * <pre>
		 * CertRepMessage ::= SEQUENCE {
		 *                          caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
		 *                                                                             OPTIONAL,
		 *                          response         SEQUENCE OF CertResponse
		 * }
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(true, 1, m_caPubs);
			v.Add(m_response);
			return new DerSequence(v);
		}
	}
}
