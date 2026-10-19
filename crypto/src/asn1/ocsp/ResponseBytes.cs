using System;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The ResponseBytes structure of RFC 6960.</summary>
    public class ResponseBytes
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="ResponseBytes"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ResponseBytes"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ResponseBytes"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ResponseBytes GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ResponseBytes responseBytes)
                return responseBytes;
            return new ResponseBytes(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ResponseBytes"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ResponseBytes"/>.</returns>
        public static ResponseBytes GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new ResponseBytes(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="ResponseBytes"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="ResponseBytes"/>, or null if <paramref name="element"/> is null.</returns>
        public static ResponseBytes GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is ResponseBytes responseBytes)
                return responseBytes;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new ResponseBytes(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="ResponseBytes"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ResponseBytes"/>.</returns>
        public static ResponseBytes GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ResponseBytes(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_responseType;
        private readonly Asn1OctetString m_response;

        /// <summary>Create a new <see cref="ResponseBytes"/>.</summary>
        /// <param name="responseType">The response type.</param>
        /// <param name="response">The response.</param>
        public ResponseBytes(DerObjectIdentifier responseType, Asn1OctetString response)
        {
            m_responseType = responseType ?? throw new ArgumentNullException(nameof(responseType));
            m_response = response ?? throw new ArgumentNullException(nameof(response));
        }

        private ResponseBytes(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_responseType = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_response = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the response type.</summary>
        public DerObjectIdentifier ResponseType => m_responseType;

        /// <summary>Gets the response.</summary>
        public Asn1OctetString Response => m_response;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * ResponseBytes ::=       Sequence {
         *     responseType   OBJECT IDENTIFIER,
         *     response       OCTET STRING }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_responseType, m_response);
    }
}
