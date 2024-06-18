using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class Attributes
        : Asn1Encodable
    {
        public static Attributes GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Attributes attributes)
                return attributes;
            return new Attributes(Asn1Set.GetInstance(obj));
        }

        public static Attributes GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new Attributes(Asn1Set.GetInstance(taggedObject, declaredExplicit));
        }

        public static Attributes GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Attributes attributes)
                return attributes;

            Asn1Set asn1Set = Asn1Set.GetOptional(element);
            if (asn1Set != null)
                return new Attributes(asn1Set);

            return null;
        }

        private readonly Asn1Set m_attributes;

        private Attributes(Asn1Set attributes)
        {
            m_attributes = attributes;
        }

        public Attributes(Asn1EncodableVector v)
        {
            m_attributes = BerSet.FromVector(v);
        }

        public virtual Attribute[] GetAttributes() => m_attributes.MapElements(Attribute.GetInstance);

        /**
         * <pre>
         * Attributes ::=
         *   SET SIZE(1..MAX) OF Attribute -- according to RFC 5652
         * </pre>
         * @return
         */
        public override Asn1Object ToAsn1Object() => m_attributes;
    }
}
