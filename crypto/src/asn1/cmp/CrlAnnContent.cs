using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The CRLAnnContent structure of RFC 4210, the body of a CRL announcement.</summary>
    public class CrlAnnContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CrlAnnContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CrlAnnContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CrlAnnContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CrlAnnContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlAnnContent crlAnnContent)
                return crlAnnContent;
            return new CrlAnnContent(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CrlAnnContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlAnnContent"/>.</returns>
        public static CrlAnnContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlAnnContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CrlAnnContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlAnnContent"/>.</returns>
        public static CrlAnnContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlAnnContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_content;

        private CrlAnnContent(Asn1Sequence seq)
        {
            m_content = seq;
        }

        /// <summary>Create a new <see cref="CrlAnnContent"/>.</summary>
        /// <param name="crl">The crl.</param>
        public CrlAnnContent(CertificateList crl)
        {
            m_content = new DerSequence(crl);
        }

        /// <summary>Return the CRLs as an array.</summary>
        /// <returns>A new array holding the CRLs.</returns>
        public virtual CertificateList[] ToCertificateListArray() => m_content.MapElements(CertificateList.GetInstance);

        /**
         * <pre>
         * CrlAnnContent ::= SEQUENCE OF CertificateList
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => m_content;
    }
}
