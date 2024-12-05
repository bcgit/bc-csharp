using System;

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
    [Obsolete("Use SLH-DSA instead")]
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

        public static SphincsPlusPublicKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SphincsPlusPublicKey(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SphincsPlusPublicKey GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is SphincsPlusPublicKey sphincsPlusPublicKey)
                return sphincsPlusPublicKey;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new SphincsPlusPublicKey(asn1Sequence);

            return null;
        }

        public static SphincsPlusPublicKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SphincsPlusPublicKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_pkseed;
        private readonly Asn1OctetString m_pkroot;

        public SphincsPlusPublicKey(byte[] pkseed, byte[] pkroot)
        {
            m_pkseed = DerOctetString.FromContents(pkseed);
            m_pkroot = DerOctetString.FromContents(pkroot);
        }

        private SphincsPlusPublicKey(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_pkseed = Asn1OctetString.GetInstance(seq[0]);
            m_pkroot = Asn1OctetString.GetInstance(seq[1]);
        }

        public byte[] GetPkroot() => Arrays.Clone(m_pkroot.GetOctets());

        public byte[] GetPkseed() => Arrays.Clone(m_pkseed.GetOctets());

        public override Asn1Object ToAsn1Object() => new DerSequence(m_pkseed, m_pkroot);
    }
}
