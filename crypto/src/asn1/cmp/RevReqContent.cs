namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The RevReqContent structure of RFC 4210, the body of a revocation request.</summary>
    public class RevReqContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="RevReqContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="RevReqContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="RevReqContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static RevReqContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RevReqContent revReqContent)
                return revReqContent;
            return new RevReqContent(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="RevReqContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RevReqContent"/>.</returns>
        public static RevReqContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RevReqContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="RevReqContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RevReqContent"/>.</returns>
        public static RevReqContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RevReqContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private RevReqContent(Asn1Sequence seq)
        {
            m_content = seq;
        }

        /// <summary>Create a new <see cref="RevReqContent"/>.</summary>
        /// <param name="revDetails">The rev details.</param>
        public RevReqContent(RevDetails revDetails)
        {
            m_content = new DerSequence(revDetails);
        }

        /// <summary>Create a new <see cref="RevReqContent"/>.</summary>
        /// <param name="revDetailsArray">The rev details array.</param>
        public RevReqContent(params RevDetails[] revDetailsArray)
        {
            m_content = new DerSequence(revDetailsArray);
        }

        public virtual RevDetails[] ToRevDetailsArray() => m_content.MapElements(RevDetails.GetInstance);

        /**
         * <pre>
         * RevReqContent ::= SEQUENCE OF RevDetails
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
