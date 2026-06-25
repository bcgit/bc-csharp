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
    /// <summary>
    /// Streaming generator for CMS EnvelopedData (PKCS#7 enveloped-data) messages. Add recipients via the base
    /// <see cref="CmsEnvelopedGenerator"/> methods, then call <see cref="Open(Stream, string)"/> to obtain a
    /// <see cref="Stream"/> to which the content to be encrypted is written; closing that stream finalizes the
    /// CMS structure.
    /// </summary>
    /// <remarks>
    /// The returned stream must be closed (disposed) to finalize the CMS structure. Closing the returned stream
    /// does <b>not</b> close the underlying stream passed to <c>Open</c>; callers are responsible for closing the
    /// underlying stream separately. If the underlying stream is a buffering encoder whose tail state only flushes
    /// on close (e.g. a base64 encoding stream), failing to close it will cause the encoded output to be truncated.
    /// <para>A simple example of usage:</para>
    /// <code>
    /// CmsEnvelopedDataStreamGenerator gen = new CmsEnvelopedDataStreamGenerator();
    /// gen.AddKeyTransRecipient(cert);
    /// using (Stream envOut = gen.Open(bOut, CmsEnvelopedGenerator.Aes128Cbc))
    /// {
    ///     envOut.Write(data, 0, data.Length);
    /// }
    /// </code>
    /// </remarks>
    public class CmsEnvelopedDataStreamGenerator
        : CmsEnvelopedGenerator
    {
        private object m_originatorInfo = null;
        private object m_unprotectedAttributes = null;
        private int m_bufferSize;
        private bool m_berEncodeRecipientSet;

        /// <summary>Creates a generator using the default randomness source.</summary>
        public CmsEnvelopedDataStreamGenerator()
        {
        }

        /// <summary>
        /// Creates a generator with an explicit randomness source for key and encryption operations.
        /// </summary>
        /// <param name="random">The secure random to use.</param>
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

        /// <summary>Controls whether recipient information is stored using a BER (indefinite-length) SET.</summary>
        /// <param name="berEncodeRecipientSet">
        /// <c>true</c> to use a BER SET; <c>false</c> to use a DER SET (the default).
        /// </param>
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

            // TODO[cms] Add 'Open' variant(s) with 'dataType' parameter
            return Open(CmsObjectIdentifiers.Data, outStream, encAlgID, cipherParameters, recipientInfos);
        }

        private Stream Open(DerObjectIdentifier dataType, Stream outStream, AlgorithmIdentifier encAlgID,
            ICipherParameters cipherParameters, Asn1EncodableVector recipientInfos)
        {
            try
            {
                // ContentInfo
                BerSequenceGenerator cGen = new BerSequenceGenerator(outStream);
                cGen.AddObject(CmsObjectIdentifiers.EnvelopedData);

                var originatorInfo = m_originatorInformation?.ToAsn1Structure();

                // EnvelopedData
                BerSequenceGenerator envGen = new BerSequenceGenerator(cGen.GetRawOutputStream(), 0, true);
                envGen.AddObject(GetVersion(originatorInfo, recipientInfos));
                CmsUtilities.AddOriginatorInfoToGenerator(envGen, originatorInfo);
                CmsUtilities.AddRecipientInfosToGenerator(envGen, recipientInfos, m_berEncodeRecipientSet);

                // EncryptedContentInfo
                BerSequenceGenerator eciGen = new BerSequenceGenerator(envGen.GetRawOutputStream());
                eciGen.AddObject(dataType);
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

        /// <summary>
        /// Opens a stream for generating a CMS EnvelopedData object, deriving a content-encryption key of the
        /// algorithm's default strength.
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <param name="encryptionOid">The content-encryption algorithm OID.</param>
        /// <returns>A stream the content to be encrypted is written to; close it to finalize the structure.</returns>
        public Stream Open(Stream outStream, string encryptionOid)
        {
            CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

            keyGen.Init(new KeyGenerationParameters(m_random, keyGen.DefaultStrength));

            return Open(outStream, encryptionOid, keyGen);
        }

        /// <summary>
        /// Opens a stream for generating a CMS EnvelopedData object, deriving a content-encryption key of the
        /// given size.
        /// </summary>
        /// <param name="outStream">The stream the CMS object is written to.</param>
        /// <param name="encryptionOid">The content-encryption algorithm OID.</param>
        /// <param name="keySize">The content-encryption key size, in bits.</param>
        /// <returns>A stream the content to be encrypted is written to; close it to finalize the structure.</returns>
        public Stream Open(Stream outStream, string encryptionOid, int keySize)
        {
            CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

            keyGen.Init(new KeyGenerationParameters(m_random, keySize));

            return Open(outStream, encryptionOid, keyGen);
        }

        private DerInteger GetVersion(OriginatorInfo originatorInfo, Asn1EncodableVector recipientInfos)
        {
            var recipientInfoSet = DLSet.FromCollection(recipientInfos);

            Asn1Set unprotectedAttrs = null;
            if (unprotectedAttributeGenerator != null)
            {
                // mark unprotected attributes as non-null.
                unprotectedAttrs = DLSet.Empty;
            }

            int version = EnvelopedData.CalculateVersion(originatorInfo, recipientInfoSet, unprotectedAttrs);

            return DerInteger.ValueOf(version);
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
