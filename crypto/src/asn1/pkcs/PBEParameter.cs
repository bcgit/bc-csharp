using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class PbeParameter
		: Asn1Encodable
	{
        public static PbeParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PbeParameter pbeParameter)
                return pbeParameter;
            return new PbeParameter(Asn1Sequence.GetInstance(obj));
        }

        public static PbeParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbeParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static PbeParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PbeParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_salt;
        private readonly DerInteger m_iterationCount;

        private PbeParameter(Asn1Sequence seq)
		{
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_salt = Asn1OctetString.GetInstance(seq[0]);
			m_iterationCount = DerInteger.GetInstance(seq[1]);
		}

		public PbeParameter(byte[] salt, int iterationCount)
		{
			m_salt = new DerOctetString(salt);
			m_iterationCount = new DerInteger(iterationCount);
		}

		public byte[] GetSalt() => m_salt.GetOctets();

		public BigInteger IterationCount => m_iterationCount.Value;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_salt, m_iterationCount);
	}
}
