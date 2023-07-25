using System;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * Implementation of the CryptoInfos element defined in RFC 4998:
     * <p/>
     * CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF Attribute
     */
    public class CryptoInfos
        : Asn1Encodable
    {
        public static CryptoInfos GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CryptoInfos cryptoInfos)
                return cryptoInfos;
            return new CryptoInfos(Asn1Sequence.GetInstance(obj));
        }

        public static CryptoInfos GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new CryptoInfos(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1Sequence m_attributes;

        private CryptoInfos(Asn1Sequence attributes)
        {
            m_attributes = attributes;
        }

        public CryptoInfos(Asn1.Cms.Attribute[] attrs)
        {
            m_attributes = new DerSequence(attrs);
        }

        public virtual Asn1.Cms.Attribute[] GetAttributes() => m_attributes.MapElements(Asn1.Cms.Attribute.GetInstance);

        public override Asn1Object ToAsn1Object() => m_attributes;
    }
}
