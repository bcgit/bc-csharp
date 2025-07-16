using System;

using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public class CertOrEncCert
		: Asn1Encodable, IAsn1Choice
	{
        public static CertOrEncCert GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static CertOrEncCert GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static CertOrEncCert GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CertOrEncCert certOrEncCert)
                return certOrEncCert;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag(0))
                    return new CertOrEncCert(CmpCertificate.GetInstance(taggedObject.GetExplicitBaseObject()));

                if (taggedObject.HasContextTag(1))
                    return new CertOrEncCert(EncryptedKey.GetInstance(taggedObject.GetExplicitBaseObject()));
            }

            return null;
        }

        public static CertOrEncCert GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly CmpCertificate m_certificate;
		private readonly EncryptedKey m_encryptedCert;

		public CertOrEncCert(CmpCertificate certificate)
		{
			m_certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        }

        [Obsolete("Use constructor with EncryptedKey instead")]
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

		public virtual bool HasEncryptedCertificate => m_encryptedCert != null;

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
