using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms.Ecc
{
    /**
     * <pre>
     *     ECC-CMS-SharedInfo ::= SEQUENCE {
     *        keyInfo AlgorithmIdentifier,
     *        entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
     *        suppPubInfo [2] EXPLICIT OCTET STRING   }
     * </pre>
     */
    public class ECC_CMS_SharedInfo
        : Asn1Encodable
    {
        public static ECC_CMS_SharedInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ECC_CMS_SharedInfo eccCmsSharedInfo)
                return eccCmsSharedInfo;
            return new ECC_CMS_SharedInfo(Asn1Sequence.GetInstance(obj));
        }

        public static ECC_CMS_SharedInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ECC_CMS_SharedInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static ECC_CMS_SharedInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ECC_CMS_SharedInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_keyInfo;
        private readonly Asn1OctetString m_entityUInfo;
        private readonly Asn1OctetString m_suppPubInfo;

        public ECC_CMS_SharedInfo(AlgorithmIdentifier keyInfo, Asn1OctetString suppPubInfo)
            : this(keyInfo, entityUInfo: null, suppPubInfo)
        {
        }

        public ECC_CMS_SharedInfo(AlgorithmIdentifier keyInfo, Asn1OctetString entityUInfo, Asn1OctetString suppPubInfo)
        {
            m_keyInfo = keyInfo ?? throw new ArgumentNullException(nameof(keyInfo));
            m_entityUInfo = entityUInfo;
            m_suppPubInfo = suppPubInfo ?? throw new ArgumentNullException(nameof(suppPubInfo));
        }

        private ECC_CMS_SharedInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keyInfo = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_entityUInfo = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1OctetString.GetTagged);
            m_suppPubInfo = Asn1Utilities.ReadContextTagged(seq, ref pos, 2, true, Asn1OctetString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_keyInfo);
            v.AddOptionalTagged(true, 0, m_entityUInfo);
            v.Add(new DerTaggedObject(true, 2, m_suppPubInfo));
            return new DerSequence(v);
        }
    }
}
