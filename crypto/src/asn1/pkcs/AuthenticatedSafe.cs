namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The AuthenticatedSafe structure of PKCS#12.</summary>
    public class AuthenticatedSafe
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="AuthenticatedSafe"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AuthenticatedSafe"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AuthenticatedSafe"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AuthenticatedSafe GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AuthenticatedSafe authenticatedSafe)
                return authenticatedSafe;
            return new AuthenticatedSafe(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="AuthenticatedSafe"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AuthenticatedSafe"/>.</returns>
        public static AuthenticatedSafe GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AuthenticatedSafe(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="AuthenticatedSafe"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AuthenticatedSafe"/>.</returns>
        public static AuthenticatedSafe GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AuthenticatedSafe(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly ContentInfo[] m_info;
        private readonly bool m_isBer;

        private AuthenticatedSafe(Asn1Sequence seq)
        {
            m_info = seq.MapElements(ContentInfo.GetInstance);
            m_isBer = seq is BerSequence;
        }

        /// <summary>Create a new <see cref="AuthenticatedSafe"/>.</summary>
        /// <param name="info">The info.</param>
        public AuthenticatedSafe(ContentInfo[] info)
        {
            m_info = Copy(info);
            m_isBer = true;
        }

        /// <summary>Return the content info.</summary>
        public ContentInfo[] GetContentInfo() => Copy(m_info);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            return m_isBer
                ?  new BerSequence(m_info)
                :  new DLSequence(m_info);
        }

        private static ContentInfo[] Copy(ContentInfo[] info) => (ContentInfo[])info.Clone();
    }
}
