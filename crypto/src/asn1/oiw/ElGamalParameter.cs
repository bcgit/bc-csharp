using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Oiw
{
    public class ElGamalParameter
        : Asn1Encodable
    {
        public static ElGamalParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ElGamalParameter elGamalParameter)
                return elGamalParameter;
#pragma warning disable CS0618 // Type or member is obsolete
            return new ElGamalParameter(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static ElGamalParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new ElGamalParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static ElGamalParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new ElGamalParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_p, m_g;

        [Obsolete("Use 'GetInstance' instead")]
        public ElGamalParameter(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_p = DerInteger.GetInstance(seq[0]);
			m_g = DerInteger.GetInstance(seq[1]);
        }

        public ElGamalParameter(BigInteger p, BigInteger g)
        {
            m_p = new DerInteger(p);
            m_g = new DerInteger(g);
        }

        public BigInteger P => m_p.PositiveValue;

		public BigInteger G => m_g.PositiveValue;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_p, m_g);
    }
}
