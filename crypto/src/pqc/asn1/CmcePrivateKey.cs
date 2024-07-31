using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

// ASN.1 Encoding for a
// Classic McEliece private key for fully populated:
// <pre>
// McEliecePrivateKey ::= SEQUENCE {
//    Version    INTEGER {v0(0)} -- version (round 3)
//    delta      OCTET STRING,   -- nonce
//    C          OCTET STRING,   -- column selections
//    g          OCTET STRING,   -- monic irreducible polynomial
//    alpha      OCTET STRING,   -- field orderings
//    s          OCTET STRING,   -- random n-bit string
//    PublicKey  [0] IMPLICIT McEliecePublicKey OPTIONAL
//                               -- see next section
//    }
// </pre>
namespace Org.BouncyCastle.Pqc.Asn1
{
    // TODO[api] Should only be Asn1Encodable
    public class CmcePrivateKey
        : Asn1Object
    {
        public static CmcePrivateKey GetInstance(Object o)
        {
            if (o == null)
                return null;
            if (o is CmcePrivateKey cmcePrivateKey)
                return cmcePrivateKey;
            return new CmcePrivateKey(Asn1Sequence.GetInstance(o));
        }

        public static CmcePrivateKey GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CmcePrivateKey(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CmcePrivateKey GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CmcePrivateKey(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_delta;
        private readonly Asn1OctetString m_c;
        private readonly Asn1OctetString m_g;
        private readonly Asn1OctetString m_alpha;
        private readonly Asn1OctetString m_s;
        private readonly CmcePublicKey m_publicKey;

        public CmcePrivateKey(int version, byte[] delta, byte[] c, byte[] g, byte[] alpha, byte[] s, CmcePublicKey pubKey = null)
        {
            if (version != 0)
                throw new Exception("unrecognized version");

            m_delta = DerOctetString.FromContents(delta);
            m_c = DerOctetString.FromContents(c);
            m_g = DerOctetString.FromContents(g);
            m_alpha = DerOctetString.FromContents(alpha);
            m_s = DerOctetString.FromContents(s);
            m_publicKey = pubKey;
        }

        private CmcePrivateKey(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 6 || count > 7)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            var version = DerInteger.GetInstance(seq[pos++]);
            m_delta = Asn1OctetString.GetInstance(seq[pos++]);
            m_c = Asn1OctetString.GetInstance(seq[pos++]);
            m_g = Asn1OctetString.GetInstance(seq[pos++]);
            m_alpha = Asn1OctetString.GetInstance(seq[pos++]);
            m_s = Asn1OctetString.GetInstance(seq[pos++]);
            m_publicKey = Asn1Utilities.ReadOptional(seq, ref pos, CmcePublicKey.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            if (!version.HasValue(0))
                throw new Exception("unrecognized version");
        }

        public int Version => 0;

        public byte[] Delta => Arrays.Clone(m_delta.GetOctets());

        public byte[] C => Arrays.Clone(m_c.GetOctets());

        public byte[] G => Arrays.Clone(m_g.GetOctets());

        public byte[] Alpha => Arrays.Clone(m_alpha.GetOctets());

        public byte[] S => Arrays.Clone(m_s.GetOctets());

        public CmcePublicKey PublicKey => m_publicKey;

        public Asn1Object ToAsn1Primitive()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(7);
            v.Add(DerInteger.Zero, m_delta, m_c, m_g, m_alpha, m_s);
            v.AddOptional(m_publicKey);
            return new DerSequence(v);
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return ToAsn1Primitive().GetEncoding(encoding);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return ToAsn1Primitive().GetEncodingImplicit(encoding, tagClass, tagNo);
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            return ToAsn1Primitive().GetEncodingDer();
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return ToAsn1Primitive().GetEncodingDerImplicit(tagClass, tagNo);
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return ToAsn1Primitive().CallAsn1Equals(asn1Object);
        }

        protected override int Asn1GetHashCode()
        {
            return ToAsn1Primitive().CallAsn1GetHashCode();
        }
    }
}
