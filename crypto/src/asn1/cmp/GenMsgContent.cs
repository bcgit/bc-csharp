namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>GenMsgContent ::= SEQUENCE OF InfoTypeAndValue</pre>
     */
    public class GenMsgContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="GenMsgContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="GenMsgContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="GenMsgContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static GenMsgContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is GenMsgContent genMsgContent)
                return genMsgContent;
            return new GenMsgContent(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="GenMsgContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="GenMsgContent"/>.</returns>
        public static GenMsgContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new GenMsgContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="GenMsgContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="GenMsgContent"/>.</returns>
        public static GenMsgContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new GenMsgContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private GenMsgContent(Asn1Sequence seq)
        {
            m_content = seq;
        }

        /// <summary>Create a new <see cref="GenMsgContent"/>.</summary>
        /// <param name="itv">The itv.</param>
        public GenMsgContent(InfoTypeAndValue itv)
        {
            m_content = new DerSequence(itv);
        }

        /// <summary>Create a new <see cref="GenMsgContent"/>.</summary>
        /// <param name="itvs">The itvs.</param>
        public GenMsgContent(params InfoTypeAndValue[] itvs)
        {
            m_content = new DerSequence(itvs);
        }

        public virtual InfoTypeAndValue[] ToInfoTypeAndValueArray() =>
            m_content.MapElements(InfoTypeAndValue.GetInstance);

        /**
         * <pre>
         * GenMsgContent ::= SEQUENCE OF InfoTypeAndValue
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
