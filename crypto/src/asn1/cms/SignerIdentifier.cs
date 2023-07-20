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

        private Asn1Encodable id;

		public SignerIdentifier(
            IssuerAndSerialNumber id)
        {
            this.id = id;
        }

		public SignerIdentifier(
            Asn1OctetString id)
        {
            this.id = new DerTaggedObject(false, 0, id);
        }

		public SignerIdentifier(
            Asn1Object id)
        {
            this.id = id;
        }

		public bool IsTagged
		{
			get { return (id is Asn1TaggedObject); }
		}

        public Asn1Encodable ID
        {
            get
            {
                if (id is Asn1TaggedObject taggedObject)
                    return Asn1OctetString.GetInstance(taggedObject, false);

                return id;
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
        public override Asn1Object ToAsn1Object()
        {
            return id.ToAsn1Object();
        }
    }
}
