using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     *    Crystal Kyber Public Key Format.
     *    See https://www.ietf.org/archive/id/draft-uni-qsckeys-kyber-00.html for details.
     *    <pre>
     *        KyberPublicKey ::= SEQUENCE {
     *         t           OCTET STRING,
     *         rho         OCTET STRING
     *     }
     *    </pre>
     */
    [Obsolete("Will be removed as this draft proposal was rejected")]
    public sealed class KyberPublicKey
        : Asn1Encodable
    {
        public static KyberPublicKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KyberPublicKey kyberPublicKey)
                return kyberPublicKey;
            return new KyberPublicKey(Asn1Sequence.GetInstance(obj));
        }

        public static KyberPublicKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly byte[] m_t;
        private readonly byte[] m_rho;

        public KyberPublicKey(byte[] t, byte[] rho)
        {
            m_t = t;
            m_rho = rho;
        }

        private KyberPublicKey(Asn1Sequence seq)
        {
            m_t = Arrays.Clone(Asn1OctetString.GetInstance(seq[0]).GetOctets());
            m_rho = Arrays.Clone(Asn1OctetString.GetInstance(seq[1]).GetOctets());
        }

        public byte[] T => Arrays.Clone(m_t);

        public byte[] Rho => Arrays.Clone(m_rho);

        public override Asn1Object ToAsn1Object()
        {
            return new DerSequence(new DerOctetString(m_t), new DerOctetString(m_rho));
        }
    }
}
