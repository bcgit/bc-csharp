using System;

namespace Org.BouncyCastle.Asn1.Ess
{
    /// <summary>The ContentIdentifier structure of RFC 2634.</summary>
    public class ContentIdentifier
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="ContentIdentifier"/> from the given object.</summary>
        /// <param name="o">
        /// An <see cref="ContentIdentifier"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ContentIdentifier"/>, or null if <paramref name="o"/> is null.</returns>
        public static ContentIdentifier GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is ContentIdentifier contentIdentifier)
                return contentIdentifier;
            return new ContentIdentifier(Asn1OctetString.GetInstance(o));
        }

        /// <summary>Return an <see cref="ContentIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ContentIdentifier"/>.</returns>
        public static ContentIdentifier GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ContentIdentifier(Asn1OctetString.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="ContentIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ContentIdentifier"/>.</returns>
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

        /// <summary>Gets the value.</summary>
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
