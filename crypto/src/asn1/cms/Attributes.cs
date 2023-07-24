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
