using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class KeyAgreeRecipientIdentifier
        : Asn1Encodable, IAsn1Choice
    {
        public static KeyAgreeRecipientIdentifier GetInstance(object obj) =>
            Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static KeyAgreeRecipientIdentifier GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            Asn1Utilities.GetInstanceChoice(obj, isExplicit, GetInstance);

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

        public static KeyAgreeRecipientIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly IssuerAndSerialNumber m_issuerSerial;
        private readonly RecipientKeyIdentifier m_rKeyID;

        public KeyAgreeRecipientIdentifier(IssuerAndSerialNumber issuerSerial)
        {
            m_issuerSerial = issuerSerial ?? throw new ArgumentNullException(nameof(issuerSerial));
        }

        public KeyAgreeRecipientIdentifier(RecipientKeyIdentifier rKeyID)
        {
            m_rKeyID = rKeyID ?? throw new ArgumentNullException(nameof(rKeyID));
        }

        public IssuerAndSerialNumber IssuerAndSerialNumber => m_issuerSerial;

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
