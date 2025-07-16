using System;
using System.IO;

using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crmf
{
    public class PkiArchiveControlBuilder
    {
        private readonly CmsEnvelopedDataGenerator m_envGen;
        private readonly CmsProcessableByteArray m_keyContent;

        /// <summary>
        ///Basic constructor - specify the contents of the PKIArchiveControl structure.
        /// </summary>
        /// <param name="privateKeyInfo">the private key to be archived.</param>
        /// <param name="generalName">the general name to be associated with the private key.</param>
        ///
        public PkiArchiveControlBuilder(PrivateKeyInfo privateKeyInfo, GeneralName generalName)
        {
            EncKeyWithID encKeyWithID = new EncKeyWithID(privateKeyInfo, generalName);

            try
            {
                m_keyContent = new CmsProcessableByteArray(CrmfObjectIdentifiers.id_ct_encKeyWithID, encKeyWithID.GetEncoded());
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("unable to encode key and general name info", e);
            }

            m_envGen = new CmsEnvelopedDataGenerator();
        }

        ///<summary>Add a recipient generator to this control.</summary>
        ///<param name="recipientGen"> recipient generator created for a specific recipient.</param>
        ///<returns>this builder object.</returns>
        public PkiArchiveControlBuilder AddRecipientGenerator(RecipientInfoGenerator recipientGen)
        {
            m_envGen.AddRecipientInfoGenerator(recipientGen);
            return this;
        }

        /// <summary>Build the PKIArchiveControl using the passed in encryptor to encrypt its contents.</summary>
        /// <param name="contentEncryptor">a suitable content encryptor.</param>
        /// <returns>a PKIArchiveControl object.</returns>
        public PkiArchiveControl Build(ICipherBuilderWithKey contentEncryptor)
        {
            CmsEnvelopedData envData = m_envGen.Generate(m_keyContent, contentEncryptor);
            var encryptedKey = new EncryptedKey(envData.EnvelopedData);
            return new PkiArchiveControl(new PkiArchiveOptions(encryptedKey));
        }

        // TODO[crmf]
#if false
        /**
         * Build the PKIArchiveControl using the passed in encryptor to encrypt its contents.
         *
         * @param contentEncryptor a suitable content encryptor.
         * @return a PKIArchiveControl object.
         * @throws CMSException in the event the build fails.
         */
        public PkiArchiveControl Build(OutputEncryptor contentEncryptor)
        {
            CmsEnvelopedData envContent = m_envGen.Generate(m_keyContent, contentEncryptor);
            EnvelopedData envD = EnvelopedData.GetInstance(envContent.ContentInfo.Content);
            return new PkiArchiveControl(new PkiArchiveOptions(new EncryptedKey(envD)));
        }
#endif
    }
}
