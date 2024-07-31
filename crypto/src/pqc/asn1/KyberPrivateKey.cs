using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     *  Crystal Kyber Private Key Format.
     *  See https://www.ietf.org/archive/id/draft-uni-qsckeys-kyber-01.html for details.
     *  <pre>
     *      KyberPrivateKey ::= SEQUENCE {
     *          version     INTEGER {v0(0)}   -- version (round 3)
     *          s           OCTET STRING,     -- sample s
     *          publicKey   [0] IMPLICIT KyberPublicKey OPTIONAL,
     *                                        -- see next section
     *          hpk         OCTET STRING      -- H(pk)
     *          nonce       OCTET STRING,     -- z
     *      }
     *  </pre>
     */
    public sealed class KyberPrivateKey
        : Asn1Encodable
    {
        public static KyberPrivateKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KyberPrivateKey kyberPublicKey)
                return kyberPublicKey;
            return new KyberPrivateKey(Asn1Sequence.GetInstance(obj));
        }

        public static KyberPrivateKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KyberPrivateKey(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static KyberPrivateKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KyberPrivateKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly Asn1OctetString m_s;
#pragma warning disable CS0618 // Type or member is obsolete
        private readonly KyberPublicKey m_publicKey;
#pragma warning restore CS0618 // Type or member is obsolete
        private readonly Asn1OctetString m_hpk;
        private readonly Asn1OctetString m_nonce;

#pragma warning disable CS0618 // Type or member is obsolete
        public KyberPrivateKey(int version, byte[] s, byte[] hpk, byte[] nonce, KyberPublicKey publicKey)
        {
            m_version = new DerInteger(version);
            m_s = DerOctetString.FromContents(s);
            m_publicKey = publicKey;
            m_hpk = DerOctetString.FromContents(hpk);
            m_nonce = DerOctetString.FromContents(nonce);
        }
#pragma warning restore CS0618 // Type or member is obsolete

        public KyberPrivateKey(int version, byte[] s, byte[] hpk, byte[] nonce)
            : this(version, s, hpk, nonce, null)
        {
        }

        private KyberPrivateKey(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 4 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            var version = DerInteger.GetInstance(seq[pos++]);
            m_s = Asn1OctetString.GetInstance(seq[pos++]);
#pragma warning disable CS0618 // Type or member is obsolete
            m_publicKey = Asn1Utilities.ReadOptional(seq, ref pos, KyberPublicKey.GetOptional);
#pragma warning restore CS0618 // Type or member is obsolete
            m_hpk = Asn1OctetString.GetInstance(seq[pos++]);
            m_nonce = Asn1OctetString.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            if (!version.HasValue(0))
                throw new Exception("unrecognized version");
        }

        public int Version => m_version.IntValueExact;

        public byte[] GetS() => Arrays.Clone(m_s.GetOctets());

#pragma warning disable CS0618 // Type or member is obsolete
        public KyberPublicKey PublicKey => m_publicKey;
#pragma warning restore CS0618 // Type or member is obsolete

        public byte[] GetHpk() => Arrays.Clone(m_hpk.GetOctets());

        public byte[] GetNonce() => Arrays.Clone(m_nonce.GetOctets());

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_version, m_s);
            v.AddOptional(m_publicKey);
            v.Add(m_hpk, m_nonce);
            return new DerSequence(v);
        }
    }
}
