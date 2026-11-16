using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The ResponseData structure of RFC 6960.</summary>
    public class ResponseData
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="ResponseData"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ResponseData"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ResponseData"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ResponseData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ResponseData responseData)
                return responseData;
            return new ResponseData(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ResponseData"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ResponseData"/>.</returns>
        public static ResponseData GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new ResponseData(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="ResponseData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ResponseData"/>.</returns>
        public static ResponseData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ResponseData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private static readonly DerInteger V1 = DerInteger.Zero;

        private readonly DerInteger m_version;
        private readonly bool m_versionPresent;
        private readonly ResponderID m_responderID;
        private readonly Asn1GeneralizedTime m_producedAt;
        private readonly Asn1Sequence m_responses;
        private readonly X509Extensions m_responseExtensions;

        /// <summary>Create a new <see cref="ResponseData"/>.</summary>
        /// <param name="responderID">The responder ID.</param>
        /// <param name="producedAt">The produced at.</param>
        /// <param name="responses">The responses.</param>
        /// <param name="responseExtensions">The response extensions.</param>
        public ResponseData(ResponderID responderID, Asn1GeneralizedTime producedAt, Asn1Sequence responses,
            X509Extensions responseExtensions)
            : this(V1, responderID, producedAt, responses, responseExtensions)
        {
        }

        /// <summary>Create a new <see cref="ResponseData"/>.</summary>
        /// <param name="version">The version.</param>
        /// <param name="responderID">The responder ID.</param>
        /// <param name="producedAt">The produced at.</param>
        /// <param name="responses">The responses.</param>
        /// <param name="responseExtensions">The response extensions.</param>
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
                DerInteger version = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, DerInteger.GetTagged);

                m_version = version ?? V1;
                m_versionPresent = version != null;
            }

            m_responderID = Asn1Utilities.Read(seq, ref pos, ResponderID.GetInstance);
            m_producedAt = Asn1Utilities.Read(seq, ref pos, Asn1GeneralizedTime.GetInstance);
            m_responses = Asn1Utilities.Read(seq, ref pos, Asn1Sequence.GetInstance);
            m_responseExtensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        /// <summary>Gets the responder ID.</summary>
        public ResponderID ResponderID => m_responderID;

        /// <summary>Gets the produced at.</summary>
        public Asn1GeneralizedTime ProducedAt => m_producedAt;

        /// <summary>Gets the responses.</summary>
        public Asn1Sequence Responses => m_responses;

        /// <summary>Gets the response extensions.</summary>
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
