using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    public class DsaParameter
        : Asn1Encodable
    {
        public static DsaParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DsaParameter dsaParameter)
                return dsaParameter;
            return new DsaParameter(Asn1Sequence.GetInstance(obj));
        }

        public static DsaParameter GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new DsaParameter(Asn1Sequence.GetInstance(obj, explicitly));

        public static DsaParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DsaParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_p, m_q, m_g;

        public DsaParameter(BigInteger p, BigInteger q, BigInteger g)
        {
            m_p = new DerInteger(p);
            m_q = new DerInteger(q);
            m_g = new DerInteger(g);
        }

        private DsaParameter(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_p = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
			m_q = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
			m_g = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

		public BigInteger P => m_p.PositiveValue;

		public BigInteger Q => m_q.PositiveValue;

		public BigInteger G => m_g.PositiveValue;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_p, m_q, m_g);
    }
}
