using System;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// <code>
    /// SignaturePolicyIdentifier ::= CHOICE {
    /// SignaturePolicyId SignaturePolicyId,
    /// SignaturePolicyImplied SignaturePolicyImplied
    /// }
    ///
    /// SignaturePolicyImplied ::= NULL
    /// </code>
    /// </remarks>
    public class SignaturePolicyIdentifier
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="SignaturePolicyIdentifier"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SignaturePolicyIdentifier"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SignaturePolicyIdentifier"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SignaturePolicyIdentifier GetInstance(object obj) =>
            Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="SignaturePolicyIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignaturePolicyIdentifier"/>.</returns>
        public static SignaturePolicyIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="SignaturePolicyIdentifier"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>
        /// The <see cref="SignaturePolicyIdentifier"/>, or null if <paramref name="element"/> is null.
        /// </returns>
        public static SignaturePolicyIdentifier GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is SignaturePolicyIdentifier signaturePolicyIdentifier)
                return signaturePolicyIdentifier;

            SignaturePolicyId signaturePolicyId = Asn1.Esf.SignaturePolicyId.GetOptional(element);
            if (signaturePolicyId != null)
                return new SignaturePolicyIdentifier(signaturePolicyId);

            Asn1Null asn1Null = Asn1Null.GetOptional(element);
            if (asn1Null != null)
                return new SignaturePolicyIdentifier();

            return null;
        }

        /// <summary>Return an <see cref="SignaturePolicyIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignaturePolicyIdentifier"/>.</returns>
        public static SignaturePolicyIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly SignaturePolicyId m_sigPolicy;

        /// <summary>Create a new <see cref="SignaturePolicyIdentifier"/>.</summary>
        public SignaturePolicyIdentifier()
        {
            m_sigPolicy = null;
        }

        /// <summary>Create a new <see cref="SignaturePolicyIdentifier"/>.</summary>
        /// <param name="signaturePolicyId">The signature policy id.</param>
        public SignaturePolicyIdentifier(SignaturePolicyId signaturePolicyId)
        {
            m_sigPolicy = signaturePolicyId ?? throw new ArgumentNullException(nameof(signaturePolicyId));
        }

        /// <summary>Gets the signature policy id.</summary>
        public SignaturePolicyId SignaturePolicyId => m_sigPolicy;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_sigPolicy?.ToAsn1Object() ?? DerNull.Instance;
    }
}
