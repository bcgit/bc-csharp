using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class OcspRequest
        : Asn1Encodable
    {
        public static OcspRequest GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OcspRequest ocspRequest)
				return ocspRequest;
			return new OcspRequest(Asn1Sequence.GetInstance(obj));
		}

        public static OcspRequest GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return new OcspRequest(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private readonly TbsRequest m_tbsRequest;
        private readonly Signature m_optionalSignature;

        public OcspRequest(TbsRequest tbsRequest, Signature optionalSignature)
        {
			m_tbsRequest = tbsRequest ?? throw new ArgumentNullException(nameof(tbsRequest));
            m_optionalSignature = optionalSignature;
        }

		private OcspRequest(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_tbsRequest = TbsRequest.GetInstance(seq[pos++]);
            m_optionalSignature = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Signature.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public TbsRequest TbsRequest => m_tbsRequest;

		public Signature OptionalSignature => m_optionalSignature;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OcspRequest     ::=     Sequence {
         *     tbsRequest                  TBSRequest,
         *     optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_tbsRequest);
            v.AddOptionalTagged(true, 0, m_optionalSignature);
            return new DerSequence(v);
        }
    }
}
