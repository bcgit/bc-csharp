using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    public class BasicOcspResponse
        : Asn1Encodable
    {
        public static BasicOcspResponse GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is BasicOcspResponse basicOcspResponse)
                return basicOcspResponse;
            return new BasicOcspResponse(Asn1Sequence.GetInstance(obj));
        }

        public static BasicOcspResponse GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return new BasicOcspResponse(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private readonly ResponseData m_tbsResponseData;
        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly DerBitString m_signature;
        private readonly Asn1Sequence m_certs;

        public BasicOcspResponse(ResponseData tbsResponseData, AlgorithmIdentifier signatureAlgorithm,
            DerBitString signature, Asn1Sequence certs)
        {
            m_tbsResponseData = tbsResponseData ?? throw new ArgumentNullException(nameof(tbsResponseData));
            m_signatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
            m_signature = signature ?? throw new ArgumentNullException(nameof(signature));
            m_certs = certs;
        }

        private BasicOcspResponse(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 3 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_tbsResponseData = ResponseData.GetInstance(seq[pos++]);
            m_signatureAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_signature = DerBitString.GetInstance(seq[pos++]);
            m_certs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1Sequence.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

		public ResponseData TbsResponseData => m_tbsResponseData;

		public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

		public DerBitString Signature => m_signature;

        public byte[] GetSignatureOctets() => m_signature.GetOctets();

        public Asn1Sequence Certs => m_certs;

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * BasicOcspResponse       ::= Sequence {
         *      tbsResponseData      ResponseData,
         *      signatureAlgorithm   AlgorithmIdentifier,
         *      signature            BIT STRING,
         *      certs                [0] EXPLICIT Sequence OF Certificate OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_tbsResponseData, m_signatureAlgorithm, m_signature);
            v.AddOptionalTagged(true, 0, m_certs);
            return new DerSequence(v);
        }
    }
}
