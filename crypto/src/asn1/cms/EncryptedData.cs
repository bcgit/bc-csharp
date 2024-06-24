using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class EncryptedData
		: Asn1Encodable
	{
        public static EncryptedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EncryptedData encryptedData)
                return encryptedData;
            return new EncryptedData(Asn1Sequence.GetInstance(obj));
        }

		public static EncryptedData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
		{
            return new EncryptedData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerInteger m_version;
        private readonly EncryptedContentInfo m_encryptedContentInfo;
        private readonly Asn1Set m_unprotectedAttrs;

        public EncryptedData(EncryptedContentInfo encInfo)
            : this(encInfo, null)
        {
        }

        public EncryptedData(EncryptedContentInfo encInfo, Asn1Set unprotectedAttrs)
        {
			m_version = unprotectedAttrs == null ? DerInteger.Zero : DerInteger.Two;
			m_encryptedContentInfo = encInfo ?? throw new ArgumentNullException(nameof(encInfo));
			m_unprotectedAttrs = unprotectedAttrs;
		}

		private EncryptedData(Asn1Sequence seq)
		{
			int count = seq.Count, pos = 0;
			if (count < 2 || count > 3)
				throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_version = DerInteger.GetInstance(seq[pos++]);
			m_encryptedContentInfo = EncryptedContentInfo.GetInstance(seq[pos++]);
			m_unprotectedAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

		public virtual DerInteger Version => m_version;

		public virtual EncryptedContentInfo EncryptedContentInfo => m_encryptedContentInfo;

		public virtual Asn1Set UnprotectedAttrs => m_unprotectedAttrs;

		/**
		* <pre>
		*       EncryptedData ::= SEQUENCE {
		*                     version CMSVersion,
		*                     encryptedContentInfo EncryptedContentInfo,
		*                     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
		* </pre>
		* @return a basic ASN.1 object representation.
		*/
		public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(3);
			v.Add(m_version, m_encryptedContentInfo);

			if (m_unprotectedAttrs != null)
			{
				v.Add(new BerTaggedObject(false, 1, m_unprotectedAttrs));
			}

			return new BerSequence(v);
		}
	}
}
