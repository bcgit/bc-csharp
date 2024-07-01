using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.CryptoPro
{
    public class ECGost3410ParamSetParameters
        : Asn1Encodable
    {
        public static ECGost3410ParamSetParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ECGost3410ParamSetParameters ecGost3410ParamSetParameters)
                return ecGost3410ParamSetParameters;
#pragma warning disable CS0618 // Type or member is obsolete
            return new ECGost3410ParamSetParameters(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static ECGost3410ParamSetParameters GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new ECGost3410ParamSetParameters(Asn1Sequence.GetInstance(obj, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static ECGost3410ParamSetParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new ECGost3410ParamSetParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_a, m_b, m_p, m_q, m_x, m_y;

        [Obsolete("Use 'GetInstance' instead")]
        public ECGost3410ParamSetParameters(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 6)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_a = DerInteger.GetInstance(seq[0]);
            m_b = DerInteger.GetInstance(seq[1]);
            m_p = DerInteger.GetInstance(seq[2]);
            m_q = DerInteger.GetInstance(seq[3]);
            m_x = DerInteger.GetInstance(seq[4]);
            m_y = DerInteger.GetInstance(seq[5]);
        }

        public ECGost3410ParamSetParameters(BigInteger a, BigInteger b, BigInteger p, BigInteger q, int x,
            BigInteger y)
        {
            m_a = new DerInteger(a);
            m_b = new DerInteger(b);
            m_p = new DerInteger(p);
            m_q = new DerInteger(q);
            m_x = new DerInteger(x);
            m_y = new DerInteger(y);
        }

        public BigInteger A => m_a.PositiveValue;

        public BigInteger B => m_b.PositiveValue;

        public BigInteger P => m_p.PositiveValue;

		public BigInteger Q => m_q.PositiveValue;

        int X => m_x.IntPositiveValueExact;

        public BigInteger Y => m_y.PositiveValue;

        public override Asn1Object ToAsn1Object() => new DerSequence(m_a, m_b, m_p, m_q, m_x, m_y);
    }
}
