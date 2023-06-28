using System;

using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class CertOrEncCert
		: Asn1Encodable, IAsn1Choice
	{
        public static CertOrEncCert GetInstance(object obj)
        {
			if (obj == null)
				return null;
            if (obj is CertOrEncCert certOrEncCert)
                return certOrEncCert;
            return new CertOrEncCert(Asn1TaggedObject.GetInstance(obj));
        }

        public static CertOrEncCert GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return Asn1Utilities.GetInstanceFromChoice(taggedObject, declaredExplicit, GetInstance);
        }

        private readonly CmpCertificate m_certificate;
		private readonly EncryptedKey m_encryptedCert;

		private CertOrEncCert(Asn1TaggedObject taggedObject)
		{
			if (taggedObject.TagNo == 0)
			{
				m_certificate = CmpCertificate.GetInstance(taggedObject.GetObject());
			}
			else if (taggedObject.TagNo == 1)
			{
                m_encryptedCert = EncryptedKey.GetInstance(taggedObject.GetObject());
			}
			else
			{
				throw new ArgumentException("unknown tag: " + taggedObject.TagNo, nameof(taggedObject));
            }
        }

		public CertOrEncCert(CmpCertificate certificate)
		{
			m_certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        }

		public CertOrEncCert(EncryptedValue encryptedValue)
		{
			m_encryptedCert = new EncryptedKey(
				encryptedValue ?? throw new ArgumentNullException(nameof(encryptedValue)));
		}

        public CertOrEncCert(EncryptedKey encryptedKey)
        {
            m_encryptedCert = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
        }

		public virtual CmpCertificate Certificate => m_certificate;

		public virtual EncryptedKey EncryptedCert => m_encryptedCert;

        /**
		 * <pre>
		 * CertOrEncCert ::= CHOICE {
		 *                      certificate     [0] CMPCertificate,
		 *                      encryptedCert   [1] EncryptedKey
		 *           }
		 * </pre>
		 * @return a basic ASN.1 object representation.
		 */
        public override Asn1Object ToAsn1Object()
		{
			if (m_certificate != null)
				return new DerTaggedObject(true, 0, m_certificate);
			if (m_encryptedCert != null)
				return new DerTaggedObject(true, 1, m_encryptedCert);
			throw new InvalidOperationException();
		}
	}
}
