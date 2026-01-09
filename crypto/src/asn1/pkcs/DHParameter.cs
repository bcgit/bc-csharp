using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class DHParameter
        : Asn1Encodable
    {
        public static DHParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DHParameter dhParameter)
                return dhParameter;
#pragma warning disable CS0618 // Type or member is obsolete
            return new DHParameter(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static DHParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new DHParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static DHParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new DHParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_p, m_g, m_l;

        public DHParameter(BigInteger p, BigInteger g, int l)
        {
            m_p = new DerInteger(p);
            m_g = new DerInteger(g);

			if (l != 0)
            {
                m_l = DerInteger.ValueOf(l);
            }
        }

        [Obsolete("Use 'GetInstance' instead")]
        public DHParameter(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_p = DerInteger.GetInstance(seq[pos++]);
            m_g = DerInteger.GetInstance(seq[pos++]);
            m_l = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public BigInteger P => m_p.PositiveValue;

        public BigInteger G => m_g.PositiveValue;

        public BigInteger L => m_l?.PositiveValue;

        public override Asn1Object ToAsn1Object()
        {
            return m_l == null
                ?  new DerSequence(m_p, m_g)
                :  new DerSequence(m_p, m_g, m_l);
        }
    }
}
