using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class ScvpReqRes
        : Asn1Encodable
    {
        public static ScvpReqRes GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ScvpReqRes scvpReqRes)
                return scvpReqRes;
            return new ScvpReqRes(Asn1Sequence.GetInstance(obj));
        }

        public static ScvpReqRes GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new ScvpReqRes(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly ContentInfo m_request;
        private readonly ContentInfo m_response;

        private ScvpReqRes(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_request = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, ContentInfo.GetInstance);
            m_response = ContentInfo.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public ScvpReqRes(ContentInfo response)
            : this(null, response)
        {
        }

        public ScvpReqRes(ContentInfo request, ContentInfo response)
        {
            m_request = request;
            m_response = response ?? throw new ArgumentNullException(nameof(response));
        }

        public virtual ContentInfo Request => m_request;

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
