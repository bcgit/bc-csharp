namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The GenRepContent structure of RFC 4210, the body of a general response.</summary>
    public class GenRepContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="GenRepContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="GenRepContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="GenRepContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static GenRepContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is GenRepContent genRepContent)
                return genRepContent;
            return new GenRepContent(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="GenRepContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="GenRepContent"/>.</returns>
        public static GenRepContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new GenRepContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="GenRepContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="GenRepContent"/>.</returns>
        public static GenRepContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new GenRepContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private GenRepContent(Asn1Sequence seq)
        {
            m_content = seq;
        }

        /// <summary>Create a new <see cref="GenRepContent"/>.</summary>
        /// <param name="itv">The itv.</param>
        public GenRepContent(InfoTypeAndValue itv)
        {
            m_content = new DerSequence(itv);
        }

        /// <summary>Create a new <see cref="GenRepContent"/>.</summary>
        /// <param name="itvs">The itvs.</param>
        public GenRepContent(params InfoTypeAndValue[] itvs)
        {
            m_content = new DerSequence(itvs);
        }

        /// <summary>Return the info type and value entries as an array.</summary>
        /// <returns>A new array holding the info type and value entries.</returns>
        public virtual InfoTypeAndValue[] ToInfoTypeAndValueArray() =>
            m_content.MapElements(InfoTypeAndValue.GetInstance);

        /**
         * <pre>
         * GenRepContent ::= SEQUENCE OF InfoTypeAndValue
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
