using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The KeyAgreeRecipientIdentifier choice of RFC 5652.</summary>
    public class KeyAgreeRecipientIdentifier
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="KeyAgreeRecipientIdentifier"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="KeyAgreeRecipientIdentifier"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="KeyAgreeRecipientIdentifier"/>, or null if <paramref name="obj"/> is null.</returns>
        public static KeyAgreeRecipientIdentifier GetInstance(object obj) =>
            Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="KeyAgreeRecipientIdentifier"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KeyAgreeRecipientIdentifier"/>.</returns>
        public static KeyAgreeRecipientIdentifier GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(obj, isExplicit, GetInstance);

        /// <summary>Return an <see cref="KeyAgreeRecipientIdentifier"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>
        /// The <see cref="KeyAgreeRecipientIdentifier"/>, or null if <paramref name="element"/> is null.
        /// </returns>
        public static KeyAgreeRecipientIdentifier GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is KeyAgreeRecipientIdentifier keyAgreeRecipientIdentifier)
                return keyAgreeRecipientIdentifier;

            IssuerAndSerialNumber issuerAndSerialNumber = IssuerAndSerialNumber.GetOptional(element);
            if (issuerAndSerialNumber != null)
                return new KeyAgreeRecipientIdentifier(issuerAndSerialNumber);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new KeyAgreeRecipientIdentifier(RecipientKeyIdentifier.GetTagged(taggedObject, false));
            }

            return null;
        }

        /// <summary>Return an <see cref="KeyAgreeRecipientIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KeyAgreeRecipientIdentifier"/>.</returns>
        public static KeyAgreeRecipientIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly IssuerAndSerialNumber m_issuerSerial;
        private readonly RecipientKeyIdentifier m_rKeyID;

        /// <summary>Create a new <see cref="KeyAgreeRecipientIdentifier"/>.</summary>
        /// <param name="issuerSerial">The issuer serial.</param>
        public KeyAgreeRecipientIdentifier(IssuerAndSerialNumber issuerSerial)
        {
            m_issuerSerial = issuerSerial ?? throw new ArgumentNullException(nameof(issuerSerial));
        }

        /// <summary>Create a new <see cref="KeyAgreeRecipientIdentifier"/>.</summary>
        /// <param name="rKeyID">The r key ID.</param>
        public KeyAgreeRecipientIdentifier(RecipientKeyIdentifier rKeyID)
        {
            m_rKeyID = rKeyID ?? throw new ArgumentNullException(nameof(rKeyID));
        }

        public IssuerAndSerialNumber IssuerAndSerialNumber => m_issuerSerial;

        /// <summary>Gets the r key ID.</summary>
        public RecipientKeyIdentifier RKeyID => m_rKeyID;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * KeyAgreeRecipientIdentifier ::= CHOICE {
         *     issuerAndSerialNumber IssuerAndSerialNumber,
         *     rKeyId [0] IMPLICIT RecipientKeyIdentifier
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_issuerSerial != null)
                return m_issuerSerial.ToAsn1Object();

            return new DerTaggedObject(false, 0, m_rKeyID);
        }
    }
}
