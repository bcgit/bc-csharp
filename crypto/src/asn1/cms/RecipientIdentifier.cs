using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class RecipientIdentifier
        : Asn1Encodable, IAsn1Choice
    {
        public static RecipientIdentifier GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is RecipientIdentifier recipientIdentifier)
                return recipientIdentifier;
            if (o is IssuerAndSerialNumber issuerAndSerialNumber)
                return new RecipientIdentifier(issuerAndSerialNumber);
            if (o is Asn1OctetString asn1OctetString)
                return new RecipientIdentifier(asn1OctetString);
            if (o is Asn1Object asn1Object)
                return new RecipientIdentifier(asn1Object);

            throw new ArgumentException("Illegal object in RecipientIdentifier: " + Platform.GetTypeName(o), nameof(o));
        }

        public static RecipientIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static RecipientIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_id;

		public RecipientIdentifier(IssuerAndSerialNumber id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

		public RecipientIdentifier(Asn1OctetString id)
        {
            m_id = new DerTaggedObject(false, 0, id);
        }

		public RecipientIdentifier(Asn1Object id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

        public bool IsTagged => m_id is Asn1TaggedObject;

		public Asn1Encodable ID
        {
            get
            {
                if (m_id is Asn1TaggedObject taggedObject)
                    return Asn1OctetString.GetInstance(taggedObject, false);

				return IssuerAndSerialNumber.GetInstance(m_id);
            }
        }

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * RecipientIdentifier ::= CHOICE {
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
