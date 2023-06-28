using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
	public class PbeParameter
		: Asn1Encodable
	{
		private readonly Asn1OctetString	salt;
		private readonly DerInteger			iterationCount;

        public static PbeParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PbeParameter pbeParameter)
                return pbeParameter;
            return new PbeParameter(Asn1Sequence.GetInstance(obj));
        }

		private PbeParameter(Asn1Sequence seq)
		{
			if (seq.Count != 2)
				throw new ArgumentException("Wrong number of elements in sequence", "seq");

			salt = Asn1OctetString.GetInstance(seq[0]);
			iterationCount = DerInteger.GetInstance(seq[1]);
		}

		public PbeParameter(byte[] salt, int iterationCount)
		{
			this.salt = new DerOctetString(salt);
			this.iterationCount = new DerInteger(iterationCount);
		}

		public byte[] GetSalt()
		{
			return salt.GetOctets();
		}

		public BigInteger IterationCount
		{
			get { return iterationCount.Value; }
		}

		public override Asn1Object ToAsn1Object()
		{
			return new DerSequence(salt, iterationCount);
		}
	}
}
