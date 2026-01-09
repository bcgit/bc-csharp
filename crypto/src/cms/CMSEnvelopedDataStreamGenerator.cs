using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Cms
{
    /**
     * General class for generating a CMS enveloped-data message stream.
     * <p>
     * A simple example of usage.
     * <pre>
     *     CmsEnvelopedDataStreamGenerator edGen = new CmsEnvelopedDataStreamGenerator();
     *     edGen.AddKeyTransRecipient(cert);
     *
     *     MemoryStream  bOut = new MemoryStream();
     *
     *     Stream out = edGen.Open(bOut, CMSEnvelopedGenerator.AES128_CBC);
     *     out.Write(data);
     *     out.Close();
     * </pre>
     * </p>
     */
    public class CmsEnvelopedDataStreamGenerator
        : CmsEnvelopedGenerator
    {
        private object m_originatorInfo = null;
        private object m_unprotectedAttributes = null;
        private int m_bufferSize;
        private bool m_berEncodeRecipientSet;

        public CmsEnvelopedDataStreamGenerator()
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        public CmsEnvelopedDataStreamGenerator(SecureRandom random)
            : base(random)
        {
        }

        /// <summary>Set the underlying string size for encapsulated data.</summary>
        /// <param name="bufferSize">Length of octet strings to buffer the data.</param>
        public void SetBufferSize(int bufferSize)
        {
            m_bufferSize = bufferSize;
        }

        /// <summary>Use a BER Set to store the recipient information.</summary>
        public void SetBerEncodeRecipients(bool berEncodeRecipientSet)
        {
            m_berEncodeRecipientSet = berEncodeRecipientSet;
        }

        /// <summary>
        /// Generate an enveloped object that contains an CMS Enveloped Data
        /// object using the passed in key generator.
        /// </summary>
        private Stream Open(Stream outStream, string encryptionOid, CipherKeyGenerator keyGen)
        {
            byte[] encKeyBytes = keyGen.GenerateKey();
            KeyParameter encKey = ParameterUtilities.CreateKeyParameter(encryptionOid, encKeyBytes);

            Asn1Encodable asn1Params = GenerateAsn1Parameters(encryptionOid, encKeyBytes);

            AlgorithmIdentifier encAlgID = GetAlgorithmIdentifier(encryptionOid, encKey, asn1Params,
                out var cipherParameters);

            // TODO[cms] Do these later when we can write each one out immediately?
            Asn1EncodableVector recipientInfos = new Asn1EncodableVector(recipientInfoGenerators.Count);

            foreach (RecipientInfoGenerator rig in recipientInfoGenerators)
            {
                try
                {
                    recipientInfos.Add(rig.Generate(encKey, m_random));
                }
                catch (InvalidKeyException e)
                {
                    throw new CmsException("key inappropriate for algorithm.", e);
                }
                catch (GeneralSecurityException e)
                {
                    throw new CmsException("error making encrypted content.", e);
                }
            }

            return Open(outStream, encAlgID, cipherParameters, recipientInfos);
        }

        private Stream Open(Stream outStream, AlgorithmIdentifier encAlgID, ICipherParameters cipherParameters,
            Asn1EncodableVector recipientInfos)
        {
            try
            {
                // ContentInfo
                BerSequenceGenerator cGen = new BerSequenceGenerator(outStream);
                cGen.AddObject(CmsObjectIdentifiers.EnvelopedData);

                // EnvelopedData
                BerSequenceGenerator envGen = new BerSequenceGenerator(cGen.GetRawOutputStream(), 0, true);

                bool isV2 = m_originatorInfo != null || m_unprotectedAttributes != null;
                var version = isV2 ? DerInteger.Two : DerInteger.Zero;

                envGen.AddObject(version);

                Stream envRaw = envGen.GetRawOutputStream();
                using (var recipGen = m_berEncodeRecipientSet
                    ? (Asn1Generator)new BerSetGenerator(envRaw)
                    : new DerSetGenerator(envRaw))
                {
                    foreach (Asn1Encodable ae in recipientInfos)
                    {
                        recipGen.AddObject(ae);
                    }
                }

                // EncryptedContentInfo
                BerSequenceGenerator eciGen = new BerSequenceGenerator(envRaw);
                eciGen.AddObject(CmsObjectIdentifiers.Data);
                eciGen.AddObject(encAlgID);

                // encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL (EncryptedContent ::= OCTET STRING)
                BerOctetStringGenerator ecGen = new BerOctetStringGenerator(eciGen.GetRawOutputStream(), 0, false);
                Stream ecStream = ecGen.GetOctetOutputStream(m_bufferSize);

                IBufferedCipher cipher = CipherUtilities.GetCipher(encAlgID.Algorithm);
                cipher.Init(true, new ParametersWithRandom(cipherParameters, m_random));
                CipherStream cOut = new CipherStream(ecStream, null, cipher);

                return new CmsEnvelopedDataOutputStream(this, cOut, cGen, envGen, eciGen, ecGen);
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
        }

        /**
         * generate an enveloped object that contains an CMS Enveloped Data object
         * @throws IOException
         */
        public Stream Open(Stream outStream, string encryptionOid)
        {
            CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

            keyGen.Init(new KeyGenerationParameters(m_random, keyGen.DefaultStrength));

            return Open(outStream, encryptionOid, keyGen);
        }

        /**
         * generate an enveloped object that contains an CMS Enveloped Data object
         * @throws IOException
         */
        public Stream Open(Stream outStream, string encryptionOid, int keySize)
        {
            CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

            keyGen.Init(new KeyGenerationParameters(m_random, keySize));

            return Open(outStream, encryptionOid, keyGen);
        }

        private class CmsEnvelopedDataOutputStream
            : BaseOutputStream
        {
            private readonly CmsEnvelopedGenerator m_outer;

            private readonly CipherStream m_out;
            private readonly BerSequenceGenerator m_cGen;
            private readonly BerSequenceGenerator m_envGen;
            private readonly BerSequenceGenerator m_eciGen;
            private readonly BerOctetStringGenerator m_ecGen;

            public CmsEnvelopedDataOutputStream(CmsEnvelopedGenerator outer, CipherStream outStream, BerSequenceGenerator cGen,
                BerSequenceGenerator envGen, BerSequenceGenerator eciGen, BerOctetStringGenerator ecGen)
            {
                m_outer = outer;
                m_out = outStream;
                m_cGen = cGen;
                m_envGen = envGen;
                m_eciGen = eciGen;
                m_ecGen = ecGen;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                m_out.Write(buffer, offset, count);
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void Write(ReadOnlySpan<byte> buffer)
            {
                m_out.Write(buffer);
            }
#endif

            public override void WriteByte(byte value)
            {
                m_out.WriteByte(value);
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    m_out.Dispose();

                    // TODO Parent context(s) should really be closed explicitly

                    m_ecGen.Dispose();
                    m_eciGen.Dispose();

                    if (m_outer.unprotectedAttributeGenerator != null)
                    {
                        Asn1.Cms.AttributeTable attrTable = m_outer.unprotectedAttributeGenerator.GetAttributes(
                            new Dictionary<CmsAttributeTableParameter, object>());

                        Asn1Set unprotectedAttrs = BerSet.FromCollection(attrTable);

                        m_envGen.AddObject(new DerTaggedObject(false, 1, unprotectedAttrs));
                    }

                    m_envGen.Dispose();
                    m_cGen.Dispose();
                }
                base.Dispose(disposing);
            }
        }
    }
}
