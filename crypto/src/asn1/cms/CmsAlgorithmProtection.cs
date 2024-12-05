using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{

    /**
     * From RFC 6211
     * <pre>
     * CMSAlgorithmProtection ::= SEQUENCE {
     *    digestAlgorithm         DigestAlgorithmIdentifier,
     *    signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
     *    macAlgorithm        [2] MessageAuthenticationCodeAlgorithm
     *                                     OPTIONAL
     * }
     * (WITH COMPONENTS { signatureAlgorithm PRESENT,
     *                    macAlgorithm ABSENT } |
     *  WITH COMPONENTS { signatureAlgorithm ABSENT,
     *                    macAlgorithm PRESENT })
     * </pre>
     */
    public class CmsAlgorithmProtection
        : Asn1Encodable
    {
        public static CmsAlgorithmProtection GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CmsAlgorithmProtection cmsAlgorithmProtection)
                return cmsAlgorithmProtection;
            return new CmsAlgorithmProtection(Asn1Sequence.GetInstance(obj));
        }

        public static CmsAlgorithmProtection GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CmsAlgorithmProtection(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CmsAlgorithmProtection GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CmsAlgorithmProtection(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public static readonly int Signature = 1;
        public static readonly int Mac = 2;

        private readonly AlgorithmIdentifier m_digestAlgorithm;
        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly AlgorithmIdentifier m_macAlgorithm;

        public CmsAlgorithmProtection(AlgorithmIdentifier digestAlgorithm, int type, AlgorithmIdentifier algorithmIdentifier)
        {
            m_digestAlgorithm = digestAlgorithm ?? throw new ArgumentNullException(nameof(digestAlgorithm));

            if (algorithmIdentifier == null)
                throw new ArgumentNullException(nameof(algorithmIdentifier));

            if (type == 1)
            {
                m_signatureAlgorithm = algorithmIdentifier;
                m_macAlgorithm = null;
            }
            else if (type == 2)
            {
                m_signatureAlgorithm = null;
                m_macAlgorithm = algorithmIdentifier;
            }
            else
            {
                throw new ArgumentException("Unknown type: " + type);
            }
        }

        private CmsAlgorithmProtection(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;

            // RFC 6211 2. Exactly one of signatureAlgorithm or macAlgorithm SHALL be present.
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_digestAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_signatureAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, AlgorithmIdentifier.GetTagged);
            m_macAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, AlgorithmIdentifier.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        public AlgorithmIdentifier MacAlgorithm => m_macAlgorithm;

        public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_digestAlgorithm);
            v.AddOptionalTagged(false, 1, m_signatureAlgorithm);
            v.AddOptionalTagged(false, 2, m_macAlgorithm);
            return new DerSequence(v);
        }
    }
}
