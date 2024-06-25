using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.IsisMtt.X509
{
    /**
	* An Admissions structure.
	* <p/>
	* <pre>
	*            Admissions ::= SEQUENCE
	*            {
	*              admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
	*              namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
	*              professionInfos SEQUENCE OF ProfessionInfo
	*            }
	* <p/>
	* </pre>
	*
	* @see Org.BouncyCastle.Asn1.IsisMtt.X509.AdmissionSyntax
	* @see Org.BouncyCastle.Asn1.IsisMtt.X509.ProfessionInfo
	* @see Org.BouncyCastle.Asn1.IsisMtt.X509.NamingAuthority
	*/
    public class Admissions
		: Asn1Encodable
	{
		public static Admissions GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is Admissions admissions)
				return admissions;
			return new Admissions(Asn1Sequence.GetInstance(obj));
		}

        public static Admissions GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Admissions(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Admissions GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Admissions(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly GeneralName m_admissionAuthority;
        private readonly NamingAuthority m_namingAuthority;
        private readonly Asn1Sequence m_professionInfos;

        /**
		* Constructor from Asn1Sequence.
		* <p/>
		* The sequence is of type ProcurationSyntax:
		* <p/>
		* <pre>
		*            Admissions ::= SEQUENCE
		*            {
		*              admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
		*              namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
		*              professionInfos SEQUENCE OF ProfessionInfo
		*            }
		* </pre>
		*
		* @param seq The ASN.1 sequence.
		*/
        private Admissions(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_admissionAuthority = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, GeneralName.GetTagged);
            m_namingAuthority = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, NamingAuthority.GetTagged);
			m_professionInfos = Asn1Sequence.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        /**
		* Constructor from a given details.
		* <p/>
		* Parameter <code>professionInfos</code> is mandatory.
		*
		* @param admissionAuthority The admission authority.
		* @param namingAuthority    The naming authority.
		* @param professionInfos    The profession infos.
		*/
        public Admissions(GeneralName admissionAuthority, NamingAuthority namingAuthority,
			ProfessionInfo[] professionInfos)
        {
            m_admissionAuthority = admissionAuthority;
            m_namingAuthority = namingAuthority;
            m_professionInfos = DerSequence.FromElements(professionInfos);
        }

		public virtual GeneralName AdmissionAuthority => m_admissionAuthority;

		public virtual NamingAuthority NamingAuthority => m_namingAuthority;

		public ProfessionInfo[] GetProfessionInfos() => m_professionInfos.MapElements(ProfessionInfo.GetInstance);

		/**
		* Produce an object suitable for an Asn1OutputStream.
		* <p/>
		* Returns:
		* <p/>
		* <pre>
		*       Admissions ::= SEQUENCE
		*       {
		*         admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
		*         namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
		*         professionInfos SEQUENCE OF ProfessionInfo
		*       }
		* <p/>
		* </pre>
		*
		* @return an Asn1Object
		*/
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(true, 0, m_admissionAuthority);
            v.AddOptionalTagged(true, 1, m_namingAuthority);
			v.Add(m_professionInfos);
			return new DerSequence(v);
		}
	}
}
