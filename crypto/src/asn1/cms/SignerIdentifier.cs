using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class SignerIdentifier
        : Asn1Encodable, IAsn1Choice
    {
        // TODO[api] Rename 'o' to 'obj'
        public static SignerIdentifier GetInstance(object o) => Asn1Utilities.GetInstanceChoice(o, GetOptional);

        public static SignerIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

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

        public static SignerIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_id;

        public SignerIdentifier(IssuerAndSerialNumber id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

        public SignerIdentifier(SubjectKeyIdentifier id)
        {
            m_id = new DerTaggedObject(false, 0, id);
        }

        [Obsolete("Use constructor taking a 'SubjectKeyIdentifier' instead")]
        public SignerIdentifier(Asn1OctetString id)
        {
            m_id = new DerTaggedObject(false, 0, id);
        }

        [Obsolete("Will be removed")]
        public SignerIdentifier(Asn1Object id)
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

                return m_id;
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
