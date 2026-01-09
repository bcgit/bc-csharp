using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class Pkcs12PbeParams
        : Asn1Encodable
    {
        public static Pkcs12PbeParams GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Pkcs12PbeParams pkcs12PbeParams)
                return pkcs12PbeParams;
            return new Pkcs12PbeParams(Asn1Sequence.GetInstance(obj));
        }

        public static Pkcs12PbeParams GetInstance(Asn1TaggedObject tagged, bool declaredExplicit) =>
            new Pkcs12PbeParams(Asn1Sequence.GetInstance(tagged, declaredExplicit));

        public static Pkcs12PbeParams GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Pkcs12PbeParams(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_iv;
        private readonly DerInteger m_iterations;

        private Pkcs12PbeParams(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_iv = Asn1OctetString.GetInstance(seq[0]);
            m_iterations = DerInteger.GetInstance(seq[1]);
        }

        public Pkcs12PbeParams(byte[] salt, int iterations)
        {
            m_iv = DerOctetString.FromContents(salt);
            m_iterations = DerInteger.ValueOf(iterations);
        }

        public BigInteger Iterations => m_iterations.Value;

        public DerInteger IterationsObject => m_iterations;

        public byte[] GetIV() => m_iv.GetOctets();

        public Asn1OctetString IV => m_iv;

        public override Asn1Object ToAsn1Object() => new DerSequence(m_iv, m_iterations);
    }
}
