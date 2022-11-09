using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class CAKeyUpdAnnContent
		: Asn1Encodable
	{
        public static CAKeyUpdAnnContent GetInstance(object obj)
        {
            if (obj is CAKeyUpdAnnContent content)
                return content;

            if (obj is Asn1Sequence seq)
                return new CAKeyUpdAnnContent(seq);

            throw new ArgumentException("Invalid object: " + Platform.GetTypeName(obj), nameof(obj));
        }

        private readonly CmpCertificate m_oldWithNew;
		private readonly CmpCertificate m_newWithOld;
		private readonly CmpCertificate m_newWithNew;

		private CAKeyUpdAnnContent(Asn1Sequence seq)
		{
			m_oldWithNew = CmpCertificate.GetInstance(seq[0]);
			m_newWithOld = CmpCertificate.GetInstance(seq[1]);
			m_newWithNew = CmpCertificate.GetInstance(seq[2]);
		}

		public virtual CmpCertificate OldWithNew => m_oldWithNew;

		public virtual CmpCertificate NewWithOld => m_newWithOld;

		public virtual CmpCertificate NewWithNew => m_newWithNew;

		/**
		 * <pre>
		 * CAKeyUpdAnnContent ::= SEQUENCE {
		 *                             oldWithNew   CmpCertificate, -- old pub signed with new priv
		 *                             newWithOld   CmpCertificate, -- new pub signed with old priv
		 *                             newWithNew   CmpCertificate  -- new pub signed with new priv
		 *  }
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
		public override Asn1Object ToAsn1Object()
		{
			return new DerSequence(m_oldWithNew, m_newWithOld, m_newWithNew);
		}
	}
}
