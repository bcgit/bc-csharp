using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Operators;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cms
{
    /// <remarks>
    /// General class for generating a CMS enveloped-data message.
    ///
    /// A simple example of usage.
    ///
    /// <pre>
    ///      CmsEnvelopedDataGenerator  fact = new CmsEnvelopedDataGenerator();
    ///
    ///      fact.AddKeyTransRecipient(cert);
    ///
    ///      CmsEnvelopedData         data = fact.Generate(content, algorithm);
    /// </pre>
    /// </remarks>
    public class CmsEnvelopedDataGenerator
        : CmsEnvelopedGenerator
    {
        public CmsEnvelopedDataGenerator()
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        public CmsEnvelopedDataGenerator(SecureRandom random)
            : base(random)
        {
        }

        /// <summary>Generate an enveloped object that contains an CMS Enveloped Data object.</summary>
        [Obsolete("Use 'Generate(CmsTypedData, DerObjectIdentifier)' instead")]
        public CmsEnvelopedData Generate(CmsProcessable content, string encryptionOid) =>
            Generate(CmsUtilities.GetTypedData(content), new DerObjectIdentifier(encryptionOid));

        /// <summary>Generate an enveloped object that contains an CMS Enveloped Data object.</summary>
        [Obsolete("Use 'Generate(CmsTypedData, DerObjectIdentifier, int)' instead")]
        public CmsEnvelopedData Generate(CmsProcessable content, string encryptionOid, int keySize) =>
            Generate(CmsUtilities.GetTypedData(content), new DerObjectIdentifier(encryptionOid), keySize);

        [Obsolete("Use 'Generate(CmsTypedData, ICipherBuilderWithKey)' instead")]
        public CmsEnvelopedData Generate(CmsProcessable content, ICipherBuilderWithKey cipherBuilder) =>
            Generate(CmsUtilities.GetTypedData(content), cipherBuilder);

        /// <summary>Generate an enveloped object that contains an CMS Enveloped Data object.</summary>
        public CmsEnvelopedData Generate(CmsTypedData content, DerObjectIdentifier encryptionOid) =>
            Generate(content, encryptionOid, keySize: -1);

        /// <summary>Generate an enveloped object that contains an CMS Enveloped Data object.</summary>
        public CmsEnvelopedData Generate(CmsTypedData content, DerObjectIdentifier encryptionOid, int keySize) =>
            Generate(content, new CmsContentEncryptorBuilder(m_random, encryptionOid, keySize).Build());

        /// <seealso cref="CmsContentEncryptorBuilder"/>
        public CmsEnvelopedData Generate(CmsTypedData content, ICipherBuilderWithKey cipherBuilder)
        {
            KeyParameter contentEncryptionKey;
            EncryptedContentInfo encryptedContentInfo;

            try
            {
                contentEncryptionKey = (KeyParameter)cipherBuilder.Key;

                var contentEncryptionAlgorithm = (AlgorithmIdentifier)cipherBuilder.AlgorithmDetails;

                MemoryStream buf = new MemoryStream();
                var cipher = cipherBuilder.BuildCipher(buf);
                using (var encryptStream = cipher.Stream)
                {
                    content.Write(encryptStream);
                }

                var encryptedContent = BerOctetString.WithContents(buf.ToArray());

                encryptedContentInfo = new EncryptedContentInfo(content.ContentType, contentEncryptionAlgorithm,
                    encryptedContent);
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("couldn't create cipher.", e);
            }
            catch (InvalidKeyException e)
            {
                throw new CmsException("key invalid in message.", e);
            }
            catch (IOException e)
            {
                throw new CmsException("exception decoding algorithm parameters.", e);
            }

            return ImplGenerate(contentEncryptionKey, encryptedContentInfo);
        }

        private CmsEnvelopedData ImplGenerate(KeyParameter contentEncryptionKey,
            EncryptedContentInfo encryptedContentInfo)
        {
            DerSet recipientInfos;
            try
            {
                recipientInfos = DerSet.Map(recipientInfoGenerators,
                    rig => rig.Generate(contentEncryptionKey, m_random));
            }
            catch (InvalidKeyException e)
            {
                throw new CmsException("key inappropriate for algorithm.", e);
            }
            catch (GeneralSecurityException e)
            {
                throw new CmsException("error making encrypted content.", e);
            }

            Asn1Set unprotectedAttrs = null;
            if (unprotectedAttributeGenerator != null)
            {
                Asn1.Cms.AttributeTable attrTable = unprotectedAttributeGenerator.GetAttributes(
                    new Dictionary<CmsAttributeTableParameter, object>());

                unprotectedAttrs = BerSet.FromCollection(attrTable);
            }

            var originatorInfo = m_originatorInformation?.ToAsn1Structure();

            var envelopedData = new EnvelopedData(originatorInfo, recipientInfos, encryptedContentInfo,
                unprotectedAttrs);

            var contentInfo = new ContentInfo(CmsObjectIdentifiers.EnvelopedData, envelopedData);

            return new CmsEnvelopedData(contentInfo);
        }
    }
}
