using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
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

        /// <summary>
        /// Generate an enveloped object that contains a CMS Enveloped Data
        /// object using the passed in key generator.
        /// </summary>
        private CmsEnvelopedData Generate(CmsProcessable content, string encryptionOid, CipherKeyGenerator keyGen)
        {
            AlgorithmIdentifier encAlgID = null;
            KeyParameter encKey;
            Asn1OctetString encryptedContent;

            try
            {
                byte[] encKeyBytes = keyGen.GenerateKey();
                encKey = ParameterUtilities.CreateKeyParameter(encryptionOid, encKeyBytes);

                Asn1Encodable asn1Params = GenerateAsn1Parameters(encryptionOid, encKeyBytes);

                encAlgID = GetAlgorithmIdentifier(encryptionOid, encKey, asn1Params, out var cipherParameters);

                IBufferedCipher cipher = CipherUtilities.GetCipher(encryptionOid);
                cipher.Init(true, new ParametersWithRandom(cipherParameters, m_random));

                MemoryStream bOut = new MemoryStream();
                using (var cOut = new CipherStream(bOut, null, cipher))
                {
                    content.Write(cOut);
                }

                encryptedContent = new BerOctetString(bOut.ToArray());
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

            DerSet recipientInfos;
            try
            {
                recipientInfos = DerSet.Map(recipientInfoGenerators, rig => rig.Generate(encKey, m_random));
            }
            catch (InvalidKeyException e)
            {
                throw new CmsException("key inappropriate for algorithm.", e);
            }
            catch (GeneralSecurityException e)
            {
                throw new CmsException("error making encrypted content.", e);
            }

            EncryptedContentInfo encryptedContentInfo = new EncryptedContentInfo(CmsObjectIdentifiers.Data, encAlgID,
                encryptedContent);

            Asn1Set unprotectedAttrs = null;
            if (unprotectedAttributeGenerator != null)
            {
                Asn1.Cms.AttributeTable attrTable = unprotectedAttributeGenerator.GetAttributes(
                    new Dictionary<CmsAttributeTableParameter, object>());

                unprotectedAttrs = BerSet.FromCollection(attrTable);
            }

            var envelopedData = new EnvelopedData(originatorInfo: null, recipientInfos, encryptedContentInfo,
                unprotectedAttrs);

            var contentInfo = new ContentInfo(CmsObjectIdentifiers.EnvelopedData, envelopedData);

            return new CmsEnvelopedData(contentInfo);
        }

        /// <summary>Generate an enveloped object that contains an CMS Enveloped Data object.</summary>
        public CmsEnvelopedData Generate(
            CmsProcessable content,
            string encryptionOid)
        {
            try
            {
                CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

                keyGen.Init(new KeyGenerationParameters(m_random, keyGen.DefaultStrength));

                return Generate(content, encryptionOid, keyGen);
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("can't find key generation algorithm.", e);
            }
        }


        public CmsEnvelopedData Generate(CmsProcessable content, ICipherBuilderWithKey cipherBuilder)
        {
            KeyParameter encKey;
            Asn1OctetString encContent;

            try
            {
                encKey = (KeyParameter)cipherBuilder.Key;

                MemoryStream collector = new MemoryStream();
                var cipher = cipherBuilder.BuildCipher(collector);
                using (var bOut = cipher.Stream)
                {
                    content.Write(bOut);
                }

                encContent = new BerOctetString(collector.ToArray());
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

            DerSet recipientInfos;
            try
            {
                recipientInfos = DerSet.Map(recipientInfoGenerators, rig => rig.Generate(encKey, m_random));
            }
            catch (InvalidKeyException e)
            {
                throw new CmsException("key inappropriate for algorithm.", e);
            }
            catch (GeneralSecurityException e)
            {
                throw new CmsException("error making encrypted content.", e);
            }

            AlgorithmIdentifier encAlgID = (AlgorithmIdentifier)cipherBuilder.AlgorithmDetails;

            EncryptedContentInfo encryptedContentInfo = new EncryptedContentInfo(CmsObjectIdentifiers.Data, encAlgID,
                encContent);

            Asn1Set unprotectedAttrs = null;
            if (unprotectedAttributeGenerator != null)
            {
                Asn1.Cms.AttributeTable attrTable = unprotectedAttributeGenerator.GetAttributes(
                    new Dictionary<CmsAttributeTableParameter, object>());

                unprotectedAttrs = BerSet.FromCollection(attrTable);
            }

            var envelopedData = new EnvelopedData(originatorInfo: null, recipientInfos, encryptedContentInfo,
                unprotectedAttrs);

            var contentInfo = new ContentInfo(CmsObjectIdentifiers.EnvelopedData, envelopedData);

            return new CmsEnvelopedData(contentInfo);
        }

        /// <summary>Generate an enveloped object that contains an CMS Enveloped Data object.</summary>
        public CmsEnvelopedData Generate(CmsProcessable content, string encryptionOid, int keySize)
        {
            try
            {
                CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

                keyGen.Init(new KeyGenerationParameters(m_random, keySize));

                return Generate(content, encryptionOid, keyGen);
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("can't find key generation algorithm.", e);
            }
        }
    }
}
