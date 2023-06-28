using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     * See https://datatracker.ietf.org/doc/draft-uni-qsckeys-sphincsplus/00/ for details.
     * ASN.1 Encoding for a
     * SphincsPlus public key for fully populated:
     * <pre>
     *   SPHINCSPPLUSPublicKey := SEQUENCE {
     *     pkseed          OCTET STRING,     --n-byte public key seed
     *     pkroot          OCTET STRING      --n-byte public hypertree root
     *   }
     * </pre>
     */
    public sealed class SphincsPlusPublicKey
        : Asn1Encodable
    {
        public static SphincsPlusPublicKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SphincsPlusPublicKey sphincsPlusPublicKey)
                return sphincsPlusPublicKey;
            return new SphincsPlusPublicKey(Asn1Sequence.GetInstance(obj));
        }

        public static SphincsPlusPublicKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly byte[] m_pkseed;
        private readonly byte[] m_pkroot;

        public SphincsPlusPublicKey(byte[] pkseed, byte[] pkroot)
        {
            m_pkseed = pkseed;
            m_pkroot = pkroot;
        }

        private SphincsPlusPublicKey(Asn1Sequence seq)
        {
            m_pkseed = Arrays.Clone(Asn1OctetString.GetInstance(seq[0]).GetOctets());
            m_pkroot = Arrays.Clone(Asn1OctetString.GetInstance(seq[1]).GetOctets());
        }

        public byte[] GetPkroot() => Arrays.Clone(m_pkroot);

        public byte[] GetPkseed() => Arrays.Clone(m_pkseed);

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(new DerOctetString(m_pkseed));
            v.Add(new DerOctetString(m_pkroot));
            return new DerSequence(v);
        }
    }
}
