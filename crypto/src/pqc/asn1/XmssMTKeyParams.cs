using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     * XMSSMTKeyParams, the algorithm parameters of the legacy XMSS^MT key encodings.
     * <pre>
     *     XMSSMTKeyParams ::= SEQUENCE {
     *         version INTEGER -- 0
     *         height INTEGER
     *         layers INTEGER
     *         treeDigest AlgorithmIdentifier
     *     }
     * </pre>
     */
    public sealed class XmssMTKeyParams
        : Asn1Encodable
    {
        public static XmssMTKeyParams GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is XmssMTKeyParams xmssMTKeyParams)
                return xmssMTKeyParams;
            return new XmssMTKeyParams(Asn1Sequence.GetInstance(obj));
        }

        public static XmssMTKeyParams GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new XmssMTKeyParams(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static XmssMTKeyParams GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new XmssMTKeyParams(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly int m_height;
        private readonly int m_layers;
        private readonly AlgorithmIdentifier m_treeDigest;

        public XmssMTKeyParams(int height, int layers, AlgorithmIdentifier treeDigest)
        {
            m_version = DerInteger.Zero;
            m_height = height;
            m_layers = layers;
            m_treeDigest = treeDigest ?? throw new ArgumentNullException(nameof(treeDigest));
        }

        private XmssMTKeyParams(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[0]);
            m_height = DerInteger.GetInstance(seq[1]).IntValueExact;
            m_layers = DerInteger.GetInstance(seq[2]).IntValueExact;
            m_treeDigest = AlgorithmIdentifier.GetInstance(seq[3]);
        }

        public int Height => m_height;

        public int Layers => m_layers;

        public AlgorithmIdentifier TreeDigest => m_treeDigest;

        public override Asn1Object ToAsn1Object() =>
            new DerSequence(m_version, DerInteger.ValueOf(m_height), DerInteger.ValueOf(m_layers), m_treeDigest);
    }
}
