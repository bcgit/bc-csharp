using System;

namespace Org.BouncyCastle.Asn1.Ess
{
    public class ContentIdentifier
		: Asn1Encodable
	{
        public static ContentIdentifier GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is ContentIdentifier contentIdentifier)
                return contentIdentifier;
            return new ContentIdentifier(Asn1OctetString.GetInstance(o));
        }

        public static ContentIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ContentIdentifier(Asn1OctetString.GetInstance(taggedObject, declaredExplicit));

        public static ContentIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ContentIdentifier(Asn1OctetString.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_value;

        /**
		 * Create from OCTET STRING whose octets represent the identifier.
		 */
        public ContentIdentifier(Asn1OctetString value)
        {
            m_value = value ?? throw new ArgumentNullException(nameof(value));
        }

        /**
		 * Create from byte array representing the identifier.
		 */
        public ContentIdentifier(byte[] value)
			: this(DerOctetString.FromContents(value))
		{
		}

		public Asn1OctetString Value => m_value;

		/**
		 * The definition of ContentIdentifier is
		 * <pre>
		 * ContentIdentifier ::=  OCTET STRING
		 * </pre>
		 * id-aa-contentIdentifier OBJECT IDENTIFIER ::= { iso(1)
		 *  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
		 *  smime(16) id-aa(2) 7 }
		 */
		public override Asn1Object ToAsn1Object() => m_value;
	}
}
