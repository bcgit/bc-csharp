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

        public static SphincsPlusPrivateKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SphincsPlusPrivateKey(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static SphincsPlusPrivateKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SphincsPlusPrivateKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public SphincsPlusPrivateKey(int version, byte[] skseed, byte[] skprf)
            : this(version, skseed, skprf, null)
        {
        }

        private readonly DerInteger m_version;
        private readonly Asn1OctetString m_skseed;
        private readonly Asn1OctetString m_skprf;
        private readonly SphincsPlusPublicKey m_publicKey;

        public SphincsPlusPrivateKey(int version, byte[] skseed, byte[] skprf, SphincsPlusPublicKey publicKey)
        {
            m_version = new DerInteger(version);
            m_skseed = DerOctetString.FromContents(skseed);
            m_skprf = DerOctetString.FromContents(skprf);
            m_publicKey = publicKey;
        }

        private SphincsPlusPrivateKey(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_skseed = Asn1OctetString.GetInstance(seq[pos++]);
            m_skprf = Asn1OctetString.GetInstance(seq[pos++]);
            m_publicKey = Asn1Utilities.ReadOptional(seq, ref pos, SphincsPlusPublicKey.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            if (!m_version.HasValue(0))
                throw new Exception("unrecognized version");
        }

        public byte[] GetSkprf() => Arrays.Clone(m_skprf.GetOctets());

        public byte[] GetSkseed() => Arrays.Clone(m_skseed.GetOctets());

        public SphincsPlusPublicKey PublicKey => m_publicKey;

        public int Version => m_version.IntValueExact;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_version, m_skseed, m_skprf);
            v.AddOptional(m_publicKey);
            return new DerSequence(v);
        }
    }
}
