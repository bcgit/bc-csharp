using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The SignerIdentifier choice of RFC 5652.</summary>
    public class SignerIdentifier
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="SignerIdentifier"/> from the given object.</summary>
        /// <param name="o">
        /// An <see cref="SignerIdentifier"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SignerIdentifier"/>, or null if <paramref name="o"/> is null.</returns>
        // TODO[api] Rename 'o' to 'obj'
        public static SignerIdentifier GetInstance(object o) => Asn1Utilities.GetInstanceChoice(o, GetOptional);

        /// <summary>Return an <see cref="SignerIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignerIdentifier"/>.</returns>
        public static SignerIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="SignerIdentifier"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="SignerIdentifier"/>, or null if <paramref name="element"/> is null.</returns>
        public static SignerIdentifier GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is SignerIdentifier signerIdentifier)
                return signerIdentifier;

            IssuerAndSerialNumber issuerAndSerialNumber = IssuerAndSerialNumber.GetOptional(element);
            if (issuerAndSerialNumber != null)
                return new SignerIdentifier(issuerAndSerialNumber);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new SignerIdentifier(SubjectKeyIdentifier.GetTagged(taggedObject, false));
            }

#pragma warning disable CS0618 // Type or member is obsolete
            // TODO[api] Remove this handler
            if (element is Asn1OctetString asn1OctetString)
                return new SignerIdentifier(asn1OctetString);
            // TODO[api] Remove this handler
            if (element is Asn1Object asn1Object)
                return new SignerIdentifier(asn1Object);
#pragma warning restore CS0618 // Type or member is obsolete

            return null;
        }

        /// <summary>Return an <see cref="SignerIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignerIdentifier"/>.</returns>
        public static SignerIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_id;

        /// <summary>Create a new <see cref="SignerIdentifier"/>.</summary>
        /// <param name="id">The id.</param>
        public SignerIdentifier(IssuerAndSerialNumber id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

        /// <summary>Create a new <see cref="SignerIdentifier"/>.</summary>
        /// <param name="id">The id.</param>
        public SignerIdentifier(SubjectKeyIdentifier id)
        {
            m_id = new DerTaggedObject(false, 0, id);
        }

        /// <summary>Create a new <see cref="SignerIdentifier"/>.</summary>
        /// <param name="id">The id.</param>
        [Obsolete("Use constructor taking a 'SubjectKeyIdentifier' instead")]
        public SignerIdentifier(Asn1OctetString id)
        {
            m_id = new DerTaggedObject(false, 0, id);
        }

        /// <summary>Create a new <see cref="SignerIdentifier"/>.</summary>
        /// <param name="id">The id.</param>
        [Obsolete("Will be removed")]
        public SignerIdentifier(Asn1Object id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

        /// <summary>Gets a value indicating whether this is tagged.</summary>
        public bool IsTagged => m_id is Asn1TaggedObject;

        /// <summary>Gets the ID.</summary>
        public Asn1Encodable ID
        {
            get
            {
                // TODO[api] Return this as a SubjectKeyIdentifier
                if (Asn1Utilities.TryGetOptionalContextTagged(m_id, 0, false, out var subjectKeyIdentifier,
                    Asn1OctetString.GetTagged))
                {
                    return subjectKeyIdentifier;
                }

                return IssuerAndSerialNumber.GetInstance(m_id);
            }
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * SignerIdentifier ::= CHOICE {
         *     issuerAndSerialNumber IssuerAndSerialNumber,
         *     subjectKeyIdentifier [0] SubjectKeyIdentifier
         * }
         *
         * SubjectKeyIdentifier ::= OCTET STRING
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => m_id.ToAsn1Object();
    }
}
