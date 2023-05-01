using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Asn1
{
    /**
     *    Crystal Kyber Private Key Format.
     *    See https://www.ietf.org/archive/id/draft-uni-qsckeys-kyber-00.html for details.
     *    <pre>
     *        KyberPrivateKey ::= SEQUENCE {
     *        version     INTEGER {v0(0)}   -- version (round 3)
     *        s           OCTET STRING,     -- EMPTY
     *        hpk         OCTET STRING      -- EMPTY
     *        nonce       OCTET STRING,     -- d
     *        publicKey   [0] IMPLICIT KyberPublicKey OPTIONAL,
     *                                      -- see next section
     *        }
     *    </pre>
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

        public static KyberPrivateKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private int version;
        private byte[] s;
#pragma warning disable CS0618 // Type or member is obsolete
        private KyberPublicKey publicKey;
#pragma warning restore CS0618 // Type or member is obsolete
        private byte[] hpk;
        private byte[] nonce;

#pragma warning disable CS0618 // Type or member is obsolete
        public KyberPrivateKey(int version, byte[] s, byte[] hpk, byte[] nonce, KyberPublicKey publicKey)
        {
            this.version = version;
            this.s = s;
            this.publicKey = publicKey;
            this.hpk = hpk;
            this.nonce = nonce;
        }
#pragma warning restore CS0618 // Type or member is obsolete

        public KyberPrivateKey(int version, byte[] s, byte[] hpk, byte[] nonce)
            : this(version, s, hpk, nonce, null)
        {
        }

        private KyberPrivateKey(Asn1Sequence seq)
        {
            version = DerInteger.GetInstance(seq[0]).IntValueExact;
            if (version != 0)
                throw new ArgumentException("unrecognized version");

            s = Arrays.Clone(Asn1OctetString.GetInstance(seq[1]).GetOctets());

            int skipPubKey = 1;
            if (seq.Count == 5)
            {
                skipPubKey = 0;
#pragma warning disable CS0618 // Type or member is obsolete
                publicKey = KyberPublicKey.GetInstance(seq[2]);
#pragma warning restore CS0618 // Type or member is obsolete
            }

            hpk = Arrays.Clone(Asn1OctetString.GetInstance(seq[3 - skipPubKey]).GetOctets());

            nonce = Arrays.Clone(Asn1OctetString.GetInstance(seq[4 - skipPubKey]).GetOctets());
        }

        public int Version => version;

        public byte[] GetS() => Arrays.Clone(s);

#pragma warning disable CS0618 // Type or member is obsolete
        public KyberPublicKey PublicKey => publicKey;
#pragma warning restore CS0618 // Type or member is obsolete

        public byte[] GetHpk() => Arrays.Clone(hpk);

        public byte[] GetNonce() => Arrays.Clone(nonce);

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);

            v.Add(new DerInteger(version));
            v.Add(new DerOctetString(s));
            if (publicKey != null)
            {
#pragma warning disable CS0618 // Type or member is obsolete
                v.Add(new KyberPublicKey(publicKey.T, publicKey.Rho));
#pragma warning restore CS0618 // Type or member is obsolete
            }
            v.Add(new DerOctetString(hpk));
            v.Add(new DerOctetString(nonce));

            return new DerSequence(v);
        }
    }
}
