using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The ScvpReqRes structure of RFC 5940.</summary>
    public class ScvpReqRes
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="ScvpReqRes"/> from the given object.</summary>
        /// <param name="obj">An <see cref="ScvpReqRes"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="ScvpReqRes"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ScvpReqRes GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ScvpReqRes scvpReqRes)
                return scvpReqRes;
            return new ScvpReqRes(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ScvpReqRes"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ScvpReqRes"/>.</returns>
        public static ScvpReqRes GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ScvpReqRes(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="ScvpReqRes"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ScvpReqRes"/>.</returns>
        public static ScvpReqRes GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ScvpReqRes(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly ContentInfo m_request;
        private readonly ContentInfo m_response;

        private ScvpReqRes(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_request = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, ContentInfo.GetTagged);
            m_response = Asn1Utilities.Read(seq, ref pos, ContentInfo.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="ScvpReqRes"/>.</summary>
        /// <param name="response">The response.</param>
        public ScvpReqRes(ContentInfo response)
            : this(null, response)
        {
        }

        /// <summary>Create a new <see cref="ScvpReqRes"/>.</summary>
        /// <param name="request">The request.</param>
        /// <param name="response">The response.</param>
        public ScvpReqRes(ContentInfo request, ContentInfo response)
        {
            m_request = request;
            m_response = response ?? throw new ArgumentNullException(nameof(response));
        }

        /// <summary>Gets the request.</summary>
        public virtual ContentInfo Request => m_request;

        /// <summary>Gets the response.</summary>
        public virtual ContentInfo Response => m_response;

        /**
         * <pre>
         *    ScvpReqRes ::= SEQUENCE {
         *    request  [0] EXPLICIT ContentInfo OPTIONAL,
         *    response     ContentInfo }
         * </pre>
         * @return  the ASN.1 primitive representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_request == null)
                return new DerSequence(m_response);

            return new DerSequence(new DerTaggedObject(true, 0, m_request), m_response);
        }
    }
}
