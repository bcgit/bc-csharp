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
    /// <summary>An RFC 3161 time-stamp token: CMS SignedData whose content is a TSTInfo, signed by the TSA.</summary>
    /// <remarks>
    /// Use <see cref="TimeStampInfo"/> to read the time-stamp details and <see cref="Validate"/> to check the token
    /// against the TSA's certificate.
    /// </remarks>
    public class TimeStampToken
    {
        private readonly CmsSignedData m_tsToken;
        private readonly SignerInformation m_tsaSignerInfo;
        private readonly TimeStampTokenInfo m_tstInfo;
        private readonly EssCertIDv2 m_certID;

        /// <summary>Create from a CMS ContentInfo structure.</summary>
        /// <param name="contentInfo">The ContentInfo wrapping the token's SignedData.</param>
        /// <exception cref="TspException">The token cannot be processed.</exception>
        /// <exception cref="TspValidationException">The content is not a valid time stamp.</exception>
        /// <exception cref="ArgumentException">The token has other than exactly one signer.</exception>
        public TimeStampToken(Asn1.Cms.ContentInfo contentInfo)
            : this(new CmsSignedData(contentInfo))
        {
        }

        /// <summary>Create from CMS SignedData.</summary>
        /// <param name="signedData">The SignedData holding the TSTInfo and the TSA's signature.</param>
        /// <exception cref="TspException">The token cannot be processed.</exception>
        /// <exception cref="TspValidationException">The content is not a valid time stamp.</exception>
        /// <exception cref="ArgumentException">The token has other than exactly one signer.</exception>
        public TimeStampToken(CmsSignedData signedData)
        {
            m_tsToken = signedData;

            if (!PkcsObjectIdentifiers.IdCTTstInfo.Equals(m_tsToken.SignedContentType))
                throw new TspValidationException("ContentInfo object not for a time stamp.");

            var signers = m_tsToken.GetSignerInfos().GetSigners();
            if (signers.Count != 1)
            {
                throw new TspValidationException(
                    $"Time-stamp token signed by {signers.Count} signers, but it must contain just the TSA signature.");
            }

            m_tsaSignerInfo = signers[0];

            try
            {
                var tstInfo = TstInfo.GetInstance(CmsUtilities.GetByteArray(m_tsToken.SignedContent));
                m_tstInfo = new TimeStampTokenInfo(tstInfo);

                var signedAttr = m_tsaSignerInfo.SignedAttributes;
                if (signedAttr == null)
                    throw new TspValidationException("no signing certificate attribute found, time stamp invalid.");

                if (signedAttr.TryGetFirst(PkcsObjectIdentifiers.IdAASigningCertificateV2, out var attrV2))
                {
                    var attrV2Values = attrV2.AttrValues;
                    if (attrV2Values.Count < 1)
                        throw new TspException("signing certificate v2 attribute MUST contain at least one AttributeValue");

                    SigningCertificateV2 signCertV2 = SigningCertificateV2.GetInstance(attrV2Values[0]);

                    var signCertV2Certs = signCertV2.GetCerts();
                    if (signCertV2Certs.Length < 1)
                        throw new TspException("signing certificate v2 attribute MUST contain at least one ESSCertIDv2");

                    m_certID = EssCertIDv2.GetInstance(signCertV2Certs[0]);
                }
                else if (signedAttr.TryGetFirst(PkcsObjectIdentifiers.IdAASigningCertificate, out var attr))
                {
                    var attrValues = attr.AttrValues;
                    if (attrValues.Count < 1)
                        throw new TspException("signing certificate attribute MUST contain at least one AttributeValue");

                    SigningCertificate signCert = SigningCertificate.GetInstance(attrValues[0]);

                    var signCertCerts = signCert.GetCerts();
                    if (signCertCerts.Length < 1)
                        throw new TspException("signing certificate attribute MUST contain at least one ESSCertID");

                    m_certID = EssCertIDv2.From(EssCertID.GetInstance(signCertCerts[0]));
                }
                else
                {
                    throw new TspValidationException("no signing certificate attribute found, time stamp invalid.");
                }
            }
            catch (CmsException e)
            {
                throw new TspException(e.Message, e.InnerException);
            }
            catch (Exception e)
            {
                throw new TspException("malformed timestamp token", e);
            }
        }

        /// <summary>Gets the time-stamp details carried in the token.</summary>
        public TimeStampTokenInfo TimeStampInfo => m_tstInfo;

        /// <summary>Gets the identifier of the TSA's signing certificate.</summary>
        public SignerID SignerID => m_tsaSignerInfo.SignerID;

        /// <summary>Gets the signed attributes of the TSA's signature.</summary>
        public Asn1.Cms.AttributeTable SignedAttributes => m_tsaSignerInfo.SignedAttributes;

        /// <summary>Gets the unsigned attributes of the TSA's signature, or null if there are none.</summary>
        public Asn1.Cms.AttributeTable UnsignedAttributes => m_tsaSignerInfo.UnsignedAttributes;

        /// <summary>Return the attribute certificates carried in the token.</summary>
        public IStore<X509V2AttributeCertificate> GetAttributeCertificates() => m_tsToken.GetAttributeCertificates();

        /// <summary>Return the certificates carried in the token.</summary>
        public IStore<X509Certificate> GetCertificates() => m_tsToken.GetCertificates();

        /// <summary>Return the CRLs carried in the token.</summary>
        public IStore<X509Crl> GetCrls() => m_tsToken.GetCrls();

        /// <summary>Validate the time stamp token.</summary>
        /// <remarks>
        /// To be valid the token must be signed by the passed in certificate and the certificate must be the one
        /// referred to by the SigningCertificate attribute included in the hashed attributes of the token. The
        /// certificate must also have the ExtendedKeyUsage extension with only KeyPurposeID.IdKPTimeStamping and have
        /// been valid at the time the timestamp was created.
        /// <para>
        /// A successful call to validate means all the above are true.
        /// </para>
        /// </remarks>
        /// <param name="cert">The certificate of the TSA.</param>
        /// <exception cref="TspValidationException">The token fails one of the checks above.</exception>
        /// <exception cref="TspException">The certificate or token cannot be processed.</exception>
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

        /// <summary>Return the underlying CmsSignedData object.</summary>
        public CmsSignedData ToCmsSignedData() => m_tsToken;

        /// <summary>Return the ASN.1 encoded representation of this object.</summary>
        public byte[] GetEncoded() => m_tsToken.GetEncoded(Asn1Encodable.DL);

        /// <summary>Return the ASN.1 encoded representation of this object using the specified encoding.</summary>
        /// <param name="encoding">The ASN.1 encoding format to use ("BER" or "DER").</param>
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
