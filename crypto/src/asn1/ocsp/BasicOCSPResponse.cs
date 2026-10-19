using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The BasicOCSPResponse structure of RFC 6960.</summary>
    public class BasicOcspResponse
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="BasicOcspResponse"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="BasicOcspResponse"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="BasicOcspResponse"/>, or null if <paramref name="obj"/> is null.</returns>
        public static BasicOcspResponse GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is BasicOcspResponse basicOcspResponse)
                return basicOcspResponse;
            return new BasicOcspResponse(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="BasicOcspResponse"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="BasicOcspResponse"/>.</returns>
        public static BasicOcspResponse GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new BasicOcspResponse(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="BasicOcspResponse"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="BasicOcspResponse"/>.</returns>
        public static BasicOcspResponse GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new BasicOcspResponse(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly ResponseData m_tbsResponseData;
        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly DerBitString m_signature;
        private readonly Asn1Sequence m_certs;

        /// <summary>Create a new <see cref="BasicOcspResponse"/>.</summary>
        /// <param name="tbsResponseData">The tbs response data.</param>
        /// <param name="signatureAlgorithm">The signature algorithm.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="certs">The certs.</param>
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

            m_tbsResponseData = Asn1Utilities.Read(seq, ref pos, ResponseData.GetInstance);
            m_signatureAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_signature = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);
            m_certs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1Sequence.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the tbs response data.</summary>
        public ResponseData TbsResponseData => m_tbsResponseData;

        /// <summary>Gets the signature algorithm.</summary>
        public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        /// <summary>Gets the signature.</summary>
        public DerBitString Signature => m_signature;

        /// <summary>Return the signature octets.</summary>
        public byte[] GetSignatureOctets() => m_signature.GetOctets();

        /// <summary>Gets the certs.</summary>
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
