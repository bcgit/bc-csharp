using System;

using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class EncryptedKey
        : Asn1Encodable, IAsn1Choice
    {
        public static EncryptedKey GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static EncryptedKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

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

        public static EncryptedKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly EnvelopedData m_envelopedData;
        private readonly EncryptedValue m_encryptedValue;

        public EncryptedKey(EnvelopedData envelopedData)
        {
            m_envelopedData = envelopedData;
        }

        public EncryptedKey(EncryptedValue encryptedValue)
        {
            m_encryptedValue = encryptedValue;
        }

        public virtual bool IsEncryptedValue => m_encryptedValue != null;

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
