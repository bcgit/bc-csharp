using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class OriginatorIdentifierOrKey
        : Asn1Encodable, IAsn1Choice
    {
        public static OriginatorIdentifierOrKey GetInstance(object o)
        {
            if (o == null)
                return null;

            if (o is OriginatorIdentifierOrKey originatorIdentifierOrKey)
                return originatorIdentifierOrKey;

            if (o is IssuerAndSerialNumber issuerAndSerialNumber)
                return new OriginatorIdentifierOrKey(issuerAndSerialNumber);

            if (o is Asn1Sequence sequence)
                return new OriginatorIdentifierOrKey(IssuerAndSerialNumber.GetInstance(sequence));

            if (o is Asn1TaggedObject taggedObject)
            {
                if (taggedObject.HasContextTag(0))
                    return new OriginatorIdentifierOrKey(SubjectKeyIdentifier.GetInstance(taggedObject, false));

                if (taggedObject.HasContextTag(1))
                    return new OriginatorIdentifierOrKey(OriginatorPublicKey.GetInstance(taggedObject, false));
            }

            throw new ArgumentException("Invalid OriginatorIdentifierOrKey: " + Platform.GetTypeName(o), nameof(o));
        }

        public static OriginatorIdentifierOrKey GetInstance(Asn1TaggedObject o, bool explicitly)
        {
            return Asn1Utilities.GetInstanceFromChoice(o, explicitly, GetInstance);
        }

        private readonly Asn1Encodable m_id;

        public OriginatorIdentifierOrKey(IssuerAndSerialNumber id)
        {
            m_id = id;
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
