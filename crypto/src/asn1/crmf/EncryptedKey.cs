using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class EncryptedKey
        : Asn1Encodable, IAsn1Choice
    {
        public static EncryptedKey GetInstance(object obj)
        {
            if (obj is EncryptedKey encryptedKey)
                return encryptedKey;

            if (obj is Asn1TaggedObject taggedObject)
                return new EncryptedKey(EnvelopedData.GetInstance(taggedObject, false));

            return new EncryptedKey(EncryptedValue.GetInstance(obj));
        }

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
