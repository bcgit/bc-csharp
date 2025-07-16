using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class RecipientIdentifier
        : Asn1Encodable, IAsn1Choice
    {
        // TODO[api] Rename 'o' to 'obj'
        public static RecipientIdentifier GetInstance(object o) => Asn1Utilities.GetInstanceChoice(o, GetOptional);

        public static RecipientIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static RecipientIdentifier GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is RecipientIdentifier recipientIdentifier)
                return recipientIdentifier;

            IssuerAndSerialNumber issuerAndSerialNumber = IssuerAndSerialNumber.GetOptional(element);
            if (issuerAndSerialNumber != null)
                return new RecipientIdentifier(issuerAndSerialNumber);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new RecipientIdentifier(SubjectKeyIdentifier.GetTagged(taggedObject, false));
            }

#pragma warning disable CS0618 // Type or member is obsolete
            // TODO[api] Remove this handler
            if (element is Asn1OctetString asn1OctetString)
                return new RecipientIdentifier(asn1OctetString);
            // TODO[api] Remove this handler
            if (element is Asn1Object asn1Object)
                return new RecipientIdentifier(asn1Object);
#pragma warning restore CS0618 // Type or member is obsolete

            return null;
        }

        public static RecipientIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_id;

		public RecipientIdentifier(IssuerAndSerialNumber id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

        public RecipientIdentifier(SubjectKeyIdentifier id)
        {
            m_id = new DerTaggedObject(false, 0, id);
        }

        [Obsolete("Use constructor taking a 'SubjectKeyIdentifier' instead")]
        public RecipientIdentifier(Asn1OctetString id)
        {
            m_id = new DerTaggedObject(false, 0, id);
        }

        [Obsolete("Will be removed")]
        public RecipientIdentifier(Asn1Object id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

        public bool IsTagged => m_id is Asn1TaggedObject;

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
