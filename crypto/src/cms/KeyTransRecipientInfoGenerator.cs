using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Generates CMS key-transport <c>RecipientInfo</c> values. Used by
    /// <see cref="CmsEnvelopedGenerator.AddKeyTransRecipient(X509Certificate)"/> and related overloads; the read-side
    /// counterpart is <see cref="KeyTransRecipientInformation"/>.
    /// </summary>
    public class KeyTransRecipientInfoGenerator
        : RecipientInfoGenerator
    {
        private readonly IKeyWrapper m_keyWrapper;

        private IssuerAndSerialNumber m_issuerAndSerialNumber;
        private SubjectKeyIdentifier m_subjectKeyIdentifier;

        /// <summary>Creates a generator that identifies the recipient from an X.509 certificate.</summary>
        /// <param name="recipCert">The recipient's public-key certificate.</param>
        /// <param name="keyWrapper">The key wrapper used to encrypt the content-encryption key.</param>
        public KeyTransRecipientInfoGenerator(X509Certificate recipCert, IKeyWrapper keyWrapper)
            : this(new IssuerAndSerialNumber(recipCert.CertificateStructure), keyWrapper)
        {
        }

        /// <summary>Creates a generator that identifies the recipient by issuer and serial number.</summary>
        /// <param name="issuerAndSerial">The recipient's issuer and serial number.</param>
        /// <param name="keyWrapper">The key wrapper used to encrypt the content-encryption key.</param>
        public KeyTransRecipientInfoGenerator(IssuerAndSerialNumber issuerAndSerial, IKeyWrapper keyWrapper)
        {
            m_issuerAndSerialNumber = issuerAndSerial;
            m_keyWrapper = keyWrapper;
        }

        /// <summary>Creates a generator that identifies the recipient by subject key identifier.</summary>
        /// <param name="subjectKeyID">The recipient's subject key identifier.</param>
        /// <param name="keyWrapper">The key wrapper used to encrypt the content-encryption key.</param>
        public KeyTransRecipientInfoGenerator(byte[] subjectKeyID, IKeyWrapper keyWrapper)
        {
            m_subjectKeyIdentifier = new SubjectKeyIdentifier(subjectKeyID);
            m_keyWrapper = keyWrapper;
        }

        /// <summary>Wraps <paramref name="contentEncryptionKey"/> and returns a key-transport RecipientInfo.</summary>
        /// <param name="contentEncryptionKey">The content-encryption key to wrap for the recipient.</param>
        /// <param name="random">A source of randomness (not used directly by this generator).</param>
        /// <returns>A CMS RecipientInfo for key transport.</returns>
        public RecipientInfo Generate(KeyParameter contentEncryptionKey, SecureRandom random)
        {
            AlgorithmIdentifier keyEncryptionAlgorithm = AlgorithmDetails;

            byte[] encryptedKeyBytes = GenerateWrappedKey(contentEncryptionKey);

            RecipientIdentifier recipId;
            if (m_issuerAndSerialNumber != null)
            {
                recipId = new RecipientIdentifier(m_issuerAndSerialNumber);
            }
            else
            {
                recipId = new RecipientIdentifier(m_subjectKeyIdentifier);
            }

            return new RecipientInfo(new KeyTransRecipientInfo(recipId, keyEncryptionAlgorithm,
                new DerOctetString(encryptedKeyBytes)));
        }

        /// <summary>Gets the key-encryption algorithm identifier from the key wrapper.</summary>
        protected virtual AlgorithmIdentifier AlgorithmDetails
        {
            get { return (AlgorithmIdentifier)m_keyWrapper.AlgorithmDetails; }
        }

        /// <summary>Wraps the content-encryption key using the configured key wrapper.</summary>
        /// <param name="contentEncryptionKey">The content-encryption key to wrap.</param>
        /// <returns>The wrapped key bytes.</returns>
        protected virtual byte[] GenerateWrappedKey(KeyParameter contentEncryptionKey)
        {
            return m_keyWrapper.Wrap(contentEncryptionKey.GetKey()).Collect();
        }
    }
}
