using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     * XMSSKeyParams, the algorithm parameters of the legacy XMSS key encodings.
     * <pre>
     *     XMSSKeyParams ::= SEQUENCE {
     *         version INTEGER -- 0
     *         height INTEGER
     *         treeDigest AlgorithmIdentifier
     *     }
     * </pre>
     */
    public sealed class XmssKeyParams
        : Asn1Encodable
    {
        public static XmssKeyParams GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is XmssKeyParams xmssKeyParams)
                return xmssKeyParams;
            return new XmssKeyParams(Asn1Sequence.GetInstance(obj));
        }

        public static XmssKeyParams GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new XmssKeyParams(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static XmssKeyParams GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new XmssKeyParams(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly int m_height;
        private readonly AlgorithmIdentifier m_treeDigest;

        public XmssKeyParams(int height, AlgorithmIdentifier treeDigest)
        {
            m_version = DerInteger.Zero;
            m_height = height;
            m_treeDigest = treeDigest ?? throw new ArgumentNullException(nameof(treeDigest));
        }

        private XmssKeyParams(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[0]);
            m_height = DerInteger.GetInstance(seq[1]).IntValueExact;
            m_treeDigest = AlgorithmIdentifier.GetInstance(seq[2]);
        }

        public int Height => m_height;

        public AlgorithmIdentifier TreeDigest => m_treeDigest;

        public override Asn1Object ToAsn1Object() =>
            new DerSequence(m_version, DerInteger.ValueOf(m_height), m_treeDigest);
    }
}
