using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tsp
{
    public class TimeStampToken
	{
        private readonly CmsSignedData m_tsToken;
        private readonly SignerInformation m_tsaSignerInfo;
        private readonly TimeStampTokenInfo m_tstInfo;
        private readonly EssCertIDv2 m_certID;

        public TimeStampToken(Asn1.Cms.ContentInfo contentInfo)
			: this(new CmsSignedData(contentInfo))
		{
		}

		public TimeStampToken(CmsSignedData signedData)
		{
			m_tsToken = signedData;

			if (!PkcsObjectIdentifiers.IdCTTstInfo.Equals(m_tsToken.SignedContentType))
				throw new TspValidationException("ContentInfo object not for a time stamp.");

			var signers = m_tsToken.GetSignerInfos().GetSigners();
			if (signers.Count != 1)
			{
				throw new ArgumentException("Time-stamp token signed by "
					+ signers.Count
					+ " signers, but it must contain just the TSA signature.");
			}

			m_tsaSignerInfo = signers[0];

			try
			{
                m_tstInfo = new TimeStampTokenInfo(TstInfo.GetInstance(CmsUtilities.GetByteArray(m_tsToken.SignedContent)));

                Asn1.Cms.Attribute attr = m_tsaSignerInfo.SignedAttributes[PkcsObjectIdentifiers.IdAASigningCertificate];

				if (attr != null)
				{
                    SigningCertificate signCert = SigningCertificate.GetInstance(attr.AttrValues[0]);
                    m_certID = EssCertIDv2.From(EssCertID.GetInstance(signCert.GetCerts()[0]));
                }
				else
				{
					attr = m_tsaSignerInfo.SignedAttributes[PkcsObjectIdentifiers.IdAASigningCertificateV2] ??
                        throw new TspValidationException("no signing certificate attribute found, time stamp invalid.");

					SigningCertificateV2 signCertV2 = SigningCertificateV2.GetInstance(attr.AttrValues[0]);
					m_certID = EssCertIDv2.GetInstance(signCertV2.GetCerts()[0]);
				}
			}
			catch (CmsException e)
			{
				throw new TspException(e.Message, e.InnerException);
			}
		}

		public TimeStampTokenInfo TimeStampInfo => m_tstInfo;

		public SignerID SignerID => m_tsaSignerInfo.SignerID;

		public Asn1.Cms.AttributeTable SignedAttributes => m_tsaSignerInfo.SignedAttributes;

		public Asn1.Cms.AttributeTable UnsignedAttributes => m_tsaSignerInfo.UnsignedAttributes;

		public IStore<X509V2AttributeCertificate> GetAttributeCertificates() => m_tsToken.GetAttributeCertificates();

		public IStore<X509Certificate> GetCertificates() => m_tsToken.GetCertificates();

		public IStore<X509Crl> GetCrls() => m_tsToken.GetCrls();

		/**
		 * Validate the time stamp token.
		 * <p>
		 * To be valid the token must be signed by the passed in certificate and
		 * the certificate must be the one referred to by the SigningCertificate
		 * attribute included in the hashed attributes of the token. The
		 * certificate must also have the ExtendedKeyUsageExtension with only
		 * KeyPurposeID.IdKPTimeStamping and have been valid at the time the
		 * timestamp was created.
		 * </p>
		 * <p>
		 * A successful call to validate means all the above are true.
		 * </p>
		 */
		public void Validate(X509Certificate cert)
		{
			try
			{
				// TODO Compare digest calculation to bc-java
				byte[] hash = DigestUtilities.CalculateDigest(m_certID.HashAlgorithm.Algorithm, cert.GetEncoded());

				if (!Arrays.FixedTimeEquals(m_certID.CertHash.GetOctets(), hash))
					throw new TspValidationException("certificate hash does not match certID hash.");

				var issuerSerial = m_certID.IssuerSerial;
				if (issuerSerial != null)
				{
					var c = cert.CertificateStructure;

					if (!issuerSerial.Serial.Equals(c.SerialNumber))
						throw new TspValidationException("certificate serial number does not match certID for signature.");

					if (!ValidateIssuer(issuerSerial.Issuer, c.Issuer))
                        throw new TspValidationException("certificate name does not match certID for signature. ");
				}

				TspUtil.ValidateCertificate(cert);

                if (!cert.IsValid(m_tstInfo.GenTime))
                    throw new TspValidationException("certificate not valid when time stamp created.");

                if (!m_tsaSignerInfo.Verify(cert))
					throw new TspValidationException("signature not created by certificate.");
			}
			catch (CmsException e)
			{
				if (e.InnerException != null)
					throw new TspException(e.Message, e.InnerException);

				throw new TspException("CMS exception: " + e, e);
			}
			catch (CertificateEncodingException e)
			{
				throw new TspException("problem processing certificate: " + e, e);
			}
			catch (SecurityUtilityException e)
			{
				throw new TspException("cannot find algorithm: " + e.Message, e);
			}
		}

		/**
		 * Return the underlying CmsSignedData object.
		 *
		 * @return the underlying CMS structure.
		 */
		public CmsSignedData ToCmsSignedData() => m_tsToken;

		/**
		 * Return a ASN.1 encoded byte stream representing the encoded object.
		 *
		 * @throws IOException if encoding fails.
		 */
		public byte[] GetEncoded() => m_tsToken.GetEncoded(Asn1Encodable.DL);

        /**
         * return the ASN.1 encoded representation of this object using the specified encoding.
         *
         * @param encoding the ASN.1 encoding format to use ("BER" or "DER").
         */
        public byte[] GetEncoded(string encoding) => m_tsToken.GetEncoded(encoding);

		private static bool ValidateIssuer(GeneralNames issuerNames, X509Name issuer)
		{
			foreach (GeneralName issuerName in issuerNames.GetNames())
			{
				if (GeneralName.DirectoryName == issuerName.TagNo &&
					X509Name.GetInstance(issuerName.Name).Equivalent(issuer))
				{
					return true;
				}
            }
			return false;
        }
    }
}
