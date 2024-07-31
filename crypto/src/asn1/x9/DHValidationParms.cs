using System;

namespace Org.BouncyCastle.Asn1.X9
{
    public class DHValidationParms
		: Asn1Encodable
	{
        public static DHValidationParms GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DHValidationParms dhValidationParms)
                return dhValidationParms;
            return new DHValidationParms(Asn1Sequence.GetInstance(obj));
        }

        public static DHValidationParms GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new DHValidationParms(Asn1Sequence.GetInstance(obj, isExplicit));

        public static DHValidationParms GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DHValidationParms accuracy)
                return accuracy;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new DHValidationParms(asn1Sequence);

            return null;
        }

        public static DHValidationParms GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DHValidationParms(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerBitString m_seed;
        private readonly DerInteger m_pgenCounter;

        private DHValidationParms(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_seed = DerBitString.GetInstance(seq[0]);
            m_pgenCounter = DerInteger.GetInstance(seq[1]);
        }

        public DHValidationParms(DerBitString seed, DerInteger pgenCounter)
		{
			m_seed = seed ?? throw new ArgumentNullException(nameof(seed));
			m_pgenCounter = pgenCounter ?? throw new ArgumentNullException(nameof(pgenCounter));
		}

        public DerBitString Seed => m_seed;

        public DerInteger PgenCounter => m_pgenCounter;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_seed, m_pgenCounter);
	}
}
