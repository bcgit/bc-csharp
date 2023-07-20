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

        private readonly ContentInfo request;
        private readonly ContentInfo response;

        private ScvpReqRes(Asn1Sequence seq)
        {
            if (seq[0] is Asn1TaggedObject taggedObject)
            {
                this.request = ContentInfo.GetInstance(taggedObject, true);
                this.response = ContentInfo.GetInstance(seq[1]);
            }
            else
            {
                this.request = null;
                this.response = ContentInfo.GetInstance(seq[0]);
            }
        }

        public ScvpReqRes(ContentInfo response)
            : this(null, response)
        {
        }

        public ScvpReqRes(ContentInfo request, ContentInfo response)
        {
            this.request = request;
            this.response = response;
        }

        public virtual ContentInfo Request
        {
            get { return request; }
        }

        public virtual ContentInfo Response
        {
            get { return response; }
        }

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
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(true, 0, request);
            v.Add(response);
            return new DerSequence(v);
        }
    }
}
