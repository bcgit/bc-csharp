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
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_salt = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
			m_iterationCount = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

		public PbeParameter(byte[] salt, int iterationCount)
		{
			m_salt = DerOctetString.FromContents(salt);
			m_iterationCount = DerInteger.ValueOf(iterationCount);
		}

		public byte[] GetSalt() => m_salt.GetOctets();

		public BigInteger IterationCount => m_iterationCount.Value;

        public DerInteger IterationCountObject => m_iterationCount;

        public Asn1OctetString Salt => m_salt;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_salt, m_iterationCount);
	}
}
