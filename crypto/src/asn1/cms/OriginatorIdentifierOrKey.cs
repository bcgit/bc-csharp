using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The OriginatorIdentifierOrKey choice of RFC 5652.</summary>
    public class OriginatorIdentifierOrKey
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="OriginatorIdentifierOrKey"/> from the given object.</summary>
        /// <param name="o">
        /// An <see cref="OriginatorIdentifierOrKey"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OriginatorIdentifierOrKey"/>, or null if <paramref name="o"/> is null.</returns>
        // TODO[api] Rename 'o' to 'obj'
        public static OriginatorIdentifierOrKey GetInstance(object o) =>
            Asn1Utilities.GetInstanceChoice(o, GetOptional);

        /// <summary>Return an <see cref="OriginatorIdentifierOrKey"/> from a tagged object.</summary>
        /// <param name="o">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OriginatorIdentifierOrKey"/>.</returns>
        public static OriginatorIdentifierOrKey GetInstance(Asn1TaggedObject o, bool explicitly) =>
            Asn1Utilities.GetInstanceChoice(o, explicitly, GetInstance);

        /// <summary>Return an <see cref="OriginatorIdentifierOrKey"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>
        /// The <see cref="OriginatorIdentifierOrKey"/>, or null if <paramref name="element"/> is null.
        /// </returns>
        public static OriginatorIdentifierOrKey GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is OriginatorIdentifierOrKey originatorIdentifierOrKey)
                return originatorIdentifierOrKey;

            IssuerAndSerialNumber issuerAndSerialNumber = IssuerAndSerialNumber.GetOptional(element);
            if (issuerAndSerialNumber != null)
                return new OriginatorIdentifierOrKey(issuerAndSerialNumber);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new OriginatorIdentifierOrKey(SubjectKeyIdentifier.GetTagged(taggedObject, false));

                if (taggedObject.HasContextTag(1))
                    return new OriginatorIdentifierOrKey(OriginatorPublicKey.GetTagged(taggedObject, false));
            }

            return null;
        }

        /// <summary>Return an <see cref="OriginatorIdentifierOrKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OriginatorIdentifierOrKey"/>.</returns>
        public static OriginatorIdentifierOrKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_id;

        /// <summary>Create a new <see cref="OriginatorIdentifierOrKey"/>.</summary>
        /// <param name="id">The id.</param>
        // TODO[api] Rename 'id' to 'issuerAndSerialNumber'
        public OriginatorIdentifierOrKey(IssuerAndSerialNumber id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

        /// <summary>Create a new <see cref="OriginatorIdentifierOrKey"/>.</summary>
        /// <param name="id">The id.</param>
        // TODO[api] Rename 'id' to 'subjectKeyIdentifier'
        public OriginatorIdentifierOrKey(SubjectKeyIdentifier id)
        {
            m_id = new DerTaggedObject(false, 0, id);
        }

        /// <summary>Create a new <see cref="OriginatorIdentifierOrKey"/>.</summary>
        /// <param name="id">The id.</param>
        // TODO[api] Rename 'id' to 'originatorKey'
        public OriginatorIdentifierOrKey(OriginatorPublicKey id)
        {
            m_id = new DerTaggedObject(false, 1, id);
        }

        /// <summary>Gets the ID.</summary>
        public Asn1Encodable ID => m_id;

        public IssuerAndSerialNumber IssuerAndSerialNumber => IssuerAndSerialNumber.GetOptional(m_id);

        /// <summary>Gets the originator key.</summary>
        public OriginatorPublicKey OriginatorKey =>
            Asn1Utilities.GetOptionalContextTagged(m_id, 1, false, OriginatorPublicKey.GetTagged);

        public SubjectKeyIdentifier SubjectKeyIdentifier =>
            Asn1Utilities.GetOptionalContextTagged(m_id, 0, false, SubjectKeyIdentifier.GetTagged);

        [Obsolete("Use 'OriginatorKey' instead")]
        public OriginatorPublicKey OriginatorPublicKey => OriginatorKey;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OriginatorIdentifierOrKey ::= CHOICE {
         *     issuerAndSerialNumber IssuerAndSerialNumber,
         *     subjectKeyIdentifier [0] SubjectKeyIdentifier,
         *     originatorKey [1] OriginatorPublicKey
         * }
         *
         * SubjectKeyIdentifier ::= OCTET STRING
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => m_id.ToAsn1Object();
    }
}
