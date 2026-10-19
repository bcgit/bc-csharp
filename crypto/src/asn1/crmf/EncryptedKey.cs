using System;

using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The EncryptedKey choice of RFC 4211: enveloped data or an encrypted value.</summary>
    public class EncryptedKey
        : Asn1Encodable, IAsn1Choice
    {
        /// <summary>Return an <see cref="EncryptedKey"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="EncryptedKey"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="EncryptedKey"/>, or null if <paramref name="obj"/> is null.</returns>
        public static EncryptedKey GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        /// <summary>Return an <see cref="EncryptedKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptedKey"/>.</returns>
        public static EncryptedKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        /// <summary>Return an <see cref="EncryptedKey"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="EncryptedKey"/>, or null if <paramref name="element"/> is null.</returns>
        public static EncryptedKey GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is EncryptedKey encryptedKey)
                return encryptedKey;

            EncryptedValue encryptedValue = EncryptedValue.GetOptional(element);
            if (encryptedValue != null)
                return new EncryptedKey(encryptedValue);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new EncryptedKey(EnvelopedData.GetTagged(taggedObject, false));
            }

            return null;
        }

        /// <summary>Return an <see cref="EncryptedKey"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EncryptedKey"/>.</returns>
        public static EncryptedKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly EnvelopedData m_envelopedData;
        private readonly EncryptedValue m_encryptedValue;

        /// <summary>Create a new <see cref="EncryptedKey"/>.</summary>
        /// <param name="envelopedData">The enveloped data.</param>
        public EncryptedKey(EnvelopedData envelopedData)
        {
            m_envelopedData = envelopedData;
        }

        /// <summary>Create a new <see cref="EncryptedKey"/>.</summary>
        /// <param name="encryptedValue">The encrypted value.</param>
        public EncryptedKey(EncryptedValue encryptedValue)
        {
            m_encryptedValue = encryptedValue;
        }

        /// <summary>Gets a value indicating whether this is encrypted value.</summary>
        public virtual bool IsEncryptedValue => m_encryptedValue != null;

        /// <summary>Gets the value.</summary>
        public virtual Asn1Encodable Value
        {
            get
            {
                if (m_encryptedValue != null)
                    return m_encryptedValue;

                return m_envelopedData;
            }
        }

        /**
         * <pre>
         *    EncryptedKey ::= CHOICE {
         *        encryptedValue        EncryptedValue, -- deprecated
         *        envelopedData     [0] EnvelopedData }
         *        -- The encrypted private key MUST be placed in the envelopedData
         *        -- encryptedContentInfo encryptedContent OCTET STRING.
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            if (m_encryptedValue != null)
                return m_encryptedValue.ToAsn1Object();

            return new DerTaggedObject(false, 0, m_envelopedData);
        }
    }
}
