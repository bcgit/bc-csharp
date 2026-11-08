using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     * XMSSMTPublicKey, the public key of the legacy key encodings.
     * <pre>
     *     XMSSMTPublicKey ::= SEQUENCE {
     *         version       INTEGER -- 0
     *         publicSeed    OCTET STRING
     *         root          OCTET STRING
     *     }
     * </pre>
     */
    public sealed class XmssMTPublicKey
        : Asn1Encodable
    {
        public static XmssMTPublicKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is XmssMTPublicKey publicKey)
                return publicKey;
            return new XmssMTPublicKey(Asn1Sequence.GetInstance(obj));
        }

        public static XmssMTPublicKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new XmssMTPublicKey(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static XmssMTPublicKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new XmssMTPublicKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly byte[] m_publicSeed;
        private readonly byte[] m_root;

        public XmssMTPublicKey(byte[] publicSeed, byte[] root)
        {
            m_publicSeed = Arrays.Clone(publicSeed ?? throw new ArgumentNullException(nameof(publicSeed)));
            m_root = Arrays.Clone(root ?? throw new ArgumentNullException(nameof(root)));
        }

        private XmssMTPublicKey(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            if (!DerInteger.GetInstance(seq[0]).HasValue(0))
                throw new ArgumentException("unknown version of sequence");

            m_publicSeed = Arrays.Clone(Asn1OctetString.GetInstance(seq[1]).GetOctets());
            m_root = Arrays.Clone(Asn1OctetString.GetInstance(seq[2]).GetOctets());
        }

        public byte[] GetPublicSeed() => Arrays.Clone(m_publicSeed);

        public byte[] GetRoot() => Arrays.Clone(m_root);

        public override Asn1Object ToAsn1Object() =>
            new DerSequence(DerInteger.Zero, new DerOctetString(m_publicSeed), new DerOctetString(m_root));
    }
}
