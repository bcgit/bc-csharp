using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The OCSPResponse structure of RFC 6960.</summary>
    public class OcspResponse
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OcspResponse"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OcspResponse"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OcspResponse"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OcspResponse GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OcspResponse ocspResponse)
                return ocspResponse;
            return new OcspResponse(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OcspResponse"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OcspResponse"/>.</returns>
        public static OcspResponse GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new OcspResponse(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="OcspResponse"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="OcspResponse"/>, or null if <paramref name="element"/> is null.</returns>
        public static OcspResponse GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is OcspResponse ocspResponse)
                return ocspResponse;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new OcspResponse(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="OcspResponse"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OcspResponse"/>.</returns>
        public static OcspResponse GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OcspResponse(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly OcspResponseStatus m_responseStatus;
        private readonly ResponseBytes m_responseBytes;

        /// <summary>Create a new <see cref="OcspResponse"/>.</summary>
        /// <param name="responseStatus">The response status.</param>
        /// <param name="responseBytes">The response bytes.</param>
        public OcspResponse(OcspResponseStatus responseStatus, ResponseBytes responseBytes)
        {
            m_responseStatus = responseStatus ?? throw new ArgumentNullException(nameof(responseStatus));
            m_responseBytes = responseBytes;
        }

        private OcspResponse(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_responseStatus = new OcspResponseStatus(Asn1Utilities.Read(seq, ref pos, DerEnumerated.GetInstance));
            m_responseBytes = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, ResponseBytes.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the response status.</summary>
        public OcspResponseStatus ResponseStatus => m_responseStatus;

        public ResponseBytes ResponseBytes => m_responseBytes;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OcspResponse ::= Sequence {
         *     responseStatus         OcspResponseStatus,
         *     responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(m_responseStatus);
            v.AddOptionalTagged(true, 0, m_responseBytes);
            return new DerSequence(v);
        }
    }
}
