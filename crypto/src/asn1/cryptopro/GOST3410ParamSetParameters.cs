using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.CryptoPro
{
    public class Gost3410ParamSetParameters
        : Asn1Encodable
    {
		public static Gost3410ParamSetParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Gost3410ParamSetParameters gost3410ParamSetParameters)
                return gost3410ParamSetParameters;
            return new Gost3410ParamSetParameters(Asn1Sequence.GetInstance(obj));
        }

        public static Gost3410ParamSetParameters GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new Gost3410ParamSetParameters(Asn1Sequence.GetInstance(obj, explicitly));

        public static Gost3410ParamSetParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Gost3410ParamSetParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly int m_keySize;
        private readonly DerInteger m_p, m_q, m_a;

		private Gost3410ParamSetParameters(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_keySize = DerInteger.GetInstance(seq[0]).IntValueExact;
			m_p = DerInteger.GetInstance(seq[1]);
            m_q = DerInteger.GetInstance(seq[2]);
			m_a = DerInteger.GetInstance(seq[3]);
        }

        public Gost3410ParamSetParameters(int keySize, BigInteger p, BigInteger q, BigInteger a)
        {
            m_keySize = keySize;
            m_p = new DerInteger(p);
            m_q = new DerInteger(q);
            m_a = new DerInteger(a);
        }

        public int KeySize => m_keySize;

		public BigInteger P => m_p.PositiveValue;

		public BigInteger Q => m_q.PositiveValue;

		public BigInteger A => m_a.PositiveValue;

		public override Asn1Object ToAsn1Object() => new DerSequence(DerInteger.ValueOf(m_keySize), m_p, m_q, m_a);
    }
}
