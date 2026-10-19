namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The POPODecKeyRespContent structure of RFC 4210, the proof-of-possession response.</summary>
    public class PopoDecKeyRespContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PopoDecKeyRespContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="PopoDecKeyRespContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="PopoDecKeyRespContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PopoDecKeyRespContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PopoDecKeyRespContent popoDecKeyRespContent)
                return popoDecKeyRespContent;
            return new PopoDecKeyRespContent(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PopoDecKeyRespContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PopoDecKeyRespContent"/>.</returns>
        public static PopoDecKeyRespContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PopoDecKeyRespContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="PopoDecKeyRespContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PopoDecKeyRespContent"/>.</returns>
        public static PopoDecKeyRespContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PopoDecKeyRespContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private PopoDecKeyRespContent(Asn1Sequence seq)
        {
            m_content = seq;
        }

        public virtual DerInteger[] ToIntegerArray() => m_content.MapElements(DerInteger.GetInstance);

        /**
         * <pre>
         * PopoDecKeyRespContent ::= SEQUENCE OF INTEGER
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
