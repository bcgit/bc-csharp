using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class ResponseData
		: Asn1Encodable
	{
        public static ResponseData GetInstance(object obj)
        {
			if (obj == null)
				return null;
            if (obj is ResponseData responseData)
                return responseData;
			return new ResponseData(Asn1Sequence.GetInstance(obj));
        }

        public static ResponseData GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return new ResponseData(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private static readonly DerInteger V1 = DerInteger.Zero;

        private readonly DerInteger m_version;
        private readonly bool m_versionPresent;
        private readonly ResponderID m_responderID;
        private readonly Asn1GeneralizedTime m_producedAt;
        private readonly Asn1Sequence m_responses;
        private readonly X509Extensions m_responseExtensions;

        public ResponseData(ResponderID responderID, Asn1GeneralizedTime producedAt, Asn1Sequence responses,
            X509Extensions responseExtensions)
            : this(V1, responderID, producedAt, responses, responseExtensions)
        {
        }

        public ResponseData(DerInteger version, ResponderID responderID, Asn1GeneralizedTime producedAt,
            Asn1Sequence responses, X509Extensions responseExtensions)
        {
            m_version = version ?? V1;
			m_versionPresent = false;
			m_responderID = responderID ?? throw new ArgumentNullException(nameof(responderID));
			m_producedAt = producedAt ?? throw new ArgumentNullException(nameof(producedAt));
			m_responses = responses ?? throw new ArgumentNullException(nameof(responses));
			m_responseExtensions = responseExtensions;
		}

        private ResponseData(Asn1Sequence seq)
		{
            int count = seq.Count;
            if (count < 3 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            {
                DerInteger version = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DerInteger.GetInstance);

                m_version = version ?? V1;
                m_versionPresent = version != null;
            }

            m_responderID = ResponderID.GetInstance(seq[pos++]);
            m_producedAt = Asn1GeneralizedTime.GetInstance(seq[pos++]);
            m_responses = Asn1Sequence.GetInstance(seq[pos++]);
            m_responseExtensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, X509Extensions.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public DerInteger Version => m_version;

		public ResponderID ResponderID => m_responderID;

		public Asn1GeneralizedTime ProducedAt => m_producedAt;

		public Asn1Sequence Responses => m_responses;

		public X509Extensions ResponseExtensions => m_responseExtensions;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * ResponseData ::= Sequence {
         *     version              [0] EXPLICIT Version DEFAULT v1,
         *     responderID              ResponderID,
         *     producedAt               GeneralizedTime,
         *     responses                Sequence OF SingleResponse,
         *     responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);

            if (m_versionPresent || !V1.Equals(m_version))
            {
                v.Add(new DerTaggedObject(true, 0, m_version));
            }

            v.Add(m_responderID, m_producedAt, m_responses);
            v.AddOptionalTagged(true, 1, m_responseExtensions);
            return new DerSequence(v);
        }
    }
}
