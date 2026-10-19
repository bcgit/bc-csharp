namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The CertConfirmContent structure of RFC 4210, carrying the certificate confirmations.</summary>
    public class CertConfirmContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertConfirmContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CertConfirmContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CertConfirmContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertConfirmContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertConfirmContent certConfirmContent)
                return certConfirmContent;
            return new CertConfirmContent(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertConfirmContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertConfirmContent"/>.</returns>
        public static CertConfirmContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertConfirmContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CertConfirmContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertConfirmContent"/>.</returns>
        public static CertConfirmContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertConfirmContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private CertConfirmContent(Asn1Sequence seq)
        {
            m_content = seq;
        }

        public virtual CertStatus[] ToCertStatusArray() => m_content.MapElements(CertStatus.GetInstance);

        /**
         * <pre>
         * CertConfirmContent ::= SEQUENCE OF CertStatus
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
