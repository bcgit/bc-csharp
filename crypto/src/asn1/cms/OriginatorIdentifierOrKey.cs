using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class OriginatorIdentifierOrKey
        : Asn1Encodable, IAsn1Choice
    {
        // TODO[api] Rename 'o' to 'obj'
        public static OriginatorIdentifierOrKey GetInstance(object o) =>
            Asn1Utilities.GetInstanceChoice(o, GetOptional);

        public static OriginatorIdentifierOrKey GetInstance(Asn1TaggedObject o, bool explicitly) =>
            Asn1Utilities.GetInstanceChoice(o, explicitly, GetInstance);

        public static OriginatorIdentifierOrKey GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is OriginatorIdentifierOrKey originatorIdentifierOrKey)
                return originatorIdentifierOrKey;

            IssuerAndSerialNumber issuerAndSerialNumber = IssuerAndSerialNumber.GetOptional(element);
            if (issuerAndSerialNumber != null)
                return new OriginatorIdentifierOrKey(issuerAndSerialNumber);

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new OriginatorIdentifierOrKey(SubjectKeyIdentifier.GetTagged(taggedObject, false));

                if (taggedObject.HasContextTag(1))
                    return new OriginatorIdentifierOrKey(OriginatorPublicKey.GetTagged(taggedObject, false));
            }

            return null;
        }

        public static OriginatorIdentifierOrKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly Asn1Encodable m_id;

        public OriginatorIdentifierOrKey(IssuerAndSerialNumber id)
        {
            m_id = id ?? throw new ArgumentNullException(nameof(id));
        }

        public OriginatorIdentifierOrKey(SubjectKeyIdentifier id)
        {
            m_id = new DerTaggedObject(false, 0, id);
        }

        public OriginatorIdentifierOrKey(OriginatorPublicKey id)
        {
            m_id = new DerTaggedObject(false, 1, id);
        }

        public Asn1Encodable ID => m_id;

        public IssuerAndSerialNumber IssuerAndSerialNumber => m_id as IssuerAndSerialNumber;

		public SubjectKeyIdentifier SubjectKeyIdentifier
		{
			get
			{
                if (m_id is Asn1TaggedObject taggedObject && taggedObject.HasContextTag(0))
                    return SubjectKeyIdentifier.GetInstance(taggedObject, false);

				return null;
			}
		}

		public OriginatorPublicKey OriginatorPublicKey
		{
			get
			{
                if (m_id is Asn1TaggedObject taggedObject && taggedObject.HasContextTag(1))
					return OriginatorPublicKey.GetInstance(taggedObject, false);

				return null;
			}
		}

		/**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * OriginatorIdentifierOrKey ::= CHOICE {
         *     issuerAndSerialNumber IssuerAndSerialNumber,
         *     subjectKeyIdentifier [0] SubjectKeyIdentifier,
         *     originatorKey [1] OriginatorPublicKey
         * }
         *
         * SubjectKeyIdentifier ::= OCTET STRING
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => m_id.ToAsn1Object();
    }
}
