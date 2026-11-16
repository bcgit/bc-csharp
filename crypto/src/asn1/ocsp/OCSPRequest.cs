using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The OCSPRequest structure of RFC 6960.</summary>
    public class OcspRequest
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OcspRequest"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OcspRequest"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OcspRequest"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OcspRequest GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OcspRequest ocspRequest)
                return ocspRequest;
            return new OcspRequest(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OcspRequest"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OcspRequest"/>.</returns>
        public static OcspRequest GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new OcspRequest(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="OcspRequest"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OcspRequest"/>.</returns>
        public static OcspRequest GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspRequest(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly TbsRequest m_tbsRequest;
        private readonly Signature m_optionalSignature;

        /// <summary>Create a new <see cref="OcspRequest"/>.</summary>
        /// <param name="tbsRequest">The tbs request.</param>
        /// <param name="optionalSignature">The optional signature.</param>
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

            m_tbsRequest = Asn1Utilities.Read(seq, ref pos, TbsRequest.GetInstance);
            m_optionalSignature = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Signature.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the tbs request.</summary>
        public TbsRequest TbsRequest => m_tbsRequest;

        /// <summary>Gets the optional signature.</summary>
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
