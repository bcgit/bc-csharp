using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     * See https://datatracker.ietf.org/doc/draft-uni-qsckeys-sphincsplus/00/ for details
     * ASN.1 Encoding for a
     * SphincsPlus private key for fully populated:
     * <pre>
     *   SPHINCSPLUSPrivateKey ::= SEQUENCE {
     *     version          INTEGER {v2(1)}     --syntax version 2 (round 3)
     *     skseed          OCTET STRING,        --n-byte private key seed
     *     skprf           OCTET STRING,        --n-byte private key seed
     *     PublicKey       SPHINCSPLUSPublicKey --public key
     *   }
     * </pre>
     */
    public sealed class SphincsPlusPrivateKey
        : Asn1Encodable
    {
        public static SphincsPlusPrivateKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SphincsPlusPrivateKey sphincsPlusPrivateKey)
                return sphincsPlusPrivateKey;
            return new SphincsPlusPrivateKey(Asn1Sequence.GetInstance(obj));
        }

        public static SphincsPlusPrivateKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        public SphincsPlusPrivateKey(int version, byte[] skseed, byte[] skprf)
            : this(version, skseed, skprf, null)
        {
        }

        public SphincsPlusPrivateKey(int version, byte[] skseed, byte[] skprf, SphincsPlusPublicKey publicKey)
        {
            m_version = version;
            m_skseed = skseed;
            m_skprf = skprf;
            m_publicKey = publicKey;
        }

        private SphincsPlusPrivateKey(Asn1Sequence seq)
        {
            m_version = DerInteger.GetInstance(seq[0]).IntValueExact;
            if (m_version != 0)
                throw new ArgumentException("unrecognized version");

            m_skseed = Arrays.Clone(Asn1OctetString.GetInstance(seq[1]).GetOctets());

            m_skprf = Arrays.Clone(Asn1OctetString.GetInstance(seq[2]).GetOctets());

            if (seq.Count == 4)
            {
                m_publicKey = SphincsPlusPublicKey.GetInstance(seq[3]);
            }
        }

        private readonly int m_version;
        private readonly byte[] m_skseed;
        private readonly byte[] m_skprf;
        private readonly SphincsPlusPublicKey m_publicKey;

        public byte[] GetSkprf() => Arrays.Clone(m_skprf);

        public byte[] GetSkseed() => Arrays.Clone(m_skseed);

        public SphincsPlusPublicKey PublicKey => m_publicKey;

        public int Version => m_version;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);

            v.Add(new DerInteger(m_version));
            v.Add(new DerOctetString(m_skseed));
            v.Add(new DerOctetString(m_skprf));

            if (m_publicKey != null)
            {
                v.Add(new SphincsPlusPublicKey(m_publicKey.GetPkseed(), m_publicKey.GetPkroot()));
            }

            return new DerSequence(v);
        }
    }
}
