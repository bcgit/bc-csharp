using System;

namespace Org.BouncyCastle.Asn1.X9
{
    public class DHDomainParameters
		: Asn1Encodable
	{
		public static DHDomainParameters GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is DHDomainParameters dhDomainParameters)
				return dhDomainParameters;
			return new DHDomainParameters(Asn1Sequence.GetInstance(obj));
		}

        public static DHDomainParameters GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new DHDomainParameters(Asn1Sequence.GetInstance(obj, isExplicit));

        public static DHDomainParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DHDomainParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_p, m_g, m_q, m_j;
        private readonly DHValidationParms m_validationParms;

        private DHDomainParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_p = DerInteger.GetInstance(seq[pos++]);
            m_g = DerInteger.GetInstance(seq[pos++]);
            m_q = DerInteger.GetInstance(seq[pos++]);
			m_j = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);
            m_validationParms = Asn1Utilities.ReadOptional(seq, ref pos, DHValidationParms.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public DHDomainParameters(DerInteger p, DerInteger g, DerInteger q, DerInteger j,
            DHValidationParms validationParms)
        {
            m_p = p ?? throw new ArgumentNullException(nameof(p));
            m_g = g ?? throw new ArgumentNullException(nameof(g));
            m_q = q ?? throw new ArgumentNullException(nameof(q));
            m_j = j;
            m_validationParms = validationParms;
        }

        public DerInteger P => m_p;

		public DerInteger G => m_g;

		public DerInteger Q => m_q;

		public DerInteger J => m_j;

        public DHValidationParms ValidationParms => m_validationParms;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_p, m_g, m_q);
            v.AddOptional(m_j, m_validationParms);
            return new DerSequence(v);
        }
	}
}
