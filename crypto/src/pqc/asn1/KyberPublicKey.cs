using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     *  Crystal Kyber Public Key Format.
     *  See https://www.ietf.org/archive/id/draft-uni-qsckeys-kyber-01.html for details.
     *  <pre>
     *      KyberPublicKey ::= SEQUENCE {
     *      t           OCTET STRING,
     *      rho         OCTET STRING
     *  }
     *  </pre>
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

        public static KyberPublicKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KyberPublicKey(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static KyberPublicKey GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is KyberPublicKey kyberPublicKey)
                return kyberPublicKey;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new KyberPublicKey(asn1Sequence);

            return null;
        }

        public static KyberPublicKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KyberPublicKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_t;
        private readonly Asn1OctetString m_rho;

        public KyberPublicKey(byte[] t, byte[] rho)
        {
            m_t = DerOctetString.FromContents(t);
            m_t = DerOctetString.FromContents(rho);
        }

        private KyberPublicKey(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_t = Asn1OctetString.GetInstance(seq[0]);
            m_rho = Asn1OctetString.GetInstance(seq[1]);
        }

        public byte[] T => Arrays.Clone(m_t.GetOctets());

        public byte[] Rho => Arrays.Clone(m_rho.GetOctets());

        public override Asn1Object ToAsn1Object() => new DerSequence(m_t, m_rho);
    }
}
