using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class SignerIdentifier
        : Asn1Encodable, IAsn1Choice
    {
        public static SignerIdentifier GetInstance(object o)
        {
            if (o == null)
                return null;

            if (o is SignerIdentifier signerIdentifier)
                return signerIdentifier;

            if (o is IssuerAndSerialNumber issuerAndSerialNumber)
                return new SignerIdentifier(issuerAndSerialNumber);

            if (o is Asn1OctetString octetString)
                return new SignerIdentifier(octetString);

            if (o is Asn1Object asn1Object)
                return new SignerIdentifier(asn1Object);

            throw new ArgumentException("Illegal object in SignerIdentifier: " + Platform.GetTypeName(o), nameof(o));
        }

        public static SignerIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return Asn1Utilities.GetInstanceFromChoice(taggedObject, declaredExplicit, GetInstance);
        }

        private readonly Asn1Encodable m_id;

        public SignerIdentifier(IssuerAndSerialNumber id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

		public SignerIdentifier(Asn1OctetString id)
        {
            m_id = new DerTaggedObject(false, 0, id);
        }

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
