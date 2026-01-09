using System;
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
     * General class for generating a CMS authenticated-data message stream.
     * <p>
     * A simple example of usage.
     * <pre>
     *     CMSAuthenticatedDataStreamGenerator edGen = new CMSAuthenticatedDataStreamGenerator();
     *     edGen.addKeyTransRecipient(cert);
     *
     *     ByteArrayOutputStream bOut = new ByteArrayOutputStream();
     *
     *     OutputStream out = edGen.open(bOut, CMSAuthenticatedDataGenerator.AES128_CBC, "BC");
     *     out.write(data);
     *     out.close();
     * </pre>
     * </p>
     */
    public class CmsAuthenticatedDataStreamGenerator
        : CmsAuthenticatedGenerator
    {
        // TODO Add support
        //private object m_originatorInfo = null;
        //private object m_unprotectedAttributes = null;
        private int m_bufferSize;
        private bool m_berEncodeRecipientSet;

        public CmsAuthenticatedDataStreamGenerator()
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        public CmsAuthenticatedDataStreamGenerator(SecureRandom random)
            : base(random)
        {
        }

        /**
         * Set the underlying string size for encapsulated data
         *
         * @param bufferSize length of octet strings to buffer the data.
         */
        public void SetBufferSize(int bufferSize)
        {
            m_bufferSize = bufferSize;
        }

        /**
         * Use a BER Set to store the recipient information
         */
        public void SetBerEncodeRecipients(bool berEncodeRecipientSet)
        {
            m_berEncodeRecipientSet = berEncodeRecipientSet;
        }

        /**
         * generate an enveloped object that contains an CMS Enveloped Data
         * object using the given provider and the passed in key generator.
         * @throws java.io.IOException
         */
        private Stream Open(Stream outStr, string macOid, CipherKeyGenerator keyGen)
        {
            // FIXME Will this work for macs?
            byte[] encKeyBytes = keyGen.GenerateKey();
            KeyParameter encKey = ParameterUtilities.CreateKeyParameter(macOid, encKeyBytes);

            Asn1Encodable asn1Params = GenerateAsn1Parameters(macOid, encKeyBytes);

            AlgorithmIdentifier macAlgID = GetAlgorithmIdentifier(macOid, encKey, asn1Params, out var cipherParameters);

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

            // FIXME Only passing key at the moment
            //return Open(outStr, macAlgId, cipherParameters, recipientInfos);
            return Open(outStr, macAlgID, encKey, recipientInfos);
        }

        // TODO[api] Presumably intended to be virtual? macAlgId -> macAlgID.
        protected Stream Open(Stream outStr, AlgorithmIdentifier macAlgId, ICipherParameters cipherParameters,
            Asn1EncodableVector recipientInfos)
        {
            try
            {
                // ContentInfo
                BerSequenceGenerator cGen = new BerSequenceGenerator(outStr);
                cGen.AddObject(CmsObjectIdentifiers.AuthenticatedData);

                // AuthenticatedData
                BerSequenceGenerator authGen = new BerSequenceGenerator(cGen.GetRawOutputStream(), 0, true);
                authGen.AddObject(DerInteger.ValueOf(AuthenticatedData.CalculateVersion(null)));

                Stream authRaw = authGen.GetRawOutputStream();
                using (var recipGen = m_berEncodeRecipientSet
                    ? (Asn1Generator)new BerSetGenerator(authRaw)
                    : new DerSetGenerator(authRaw))
                {
                    foreach (Asn1Encodable ae in recipientInfos)
                    {
                        recipGen.AddObject(ae);
                    }
                }

                authGen.AddObject(macAlgId);

                // EncapsulatedContentInfo
                BerSequenceGenerator eciGen = new BerSequenceGenerator(authRaw);
                eciGen.AddObject(CmsObjectIdentifiers.Data);

                // eContent [0] EXPLICIT OCTET STRING OPTIONAL
                BerOctetStringGenerator ecGen = new BerOctetStringGenerator(eciGen.GetRawOutputStream(), 0, true);
                Stream ecStream = ecGen.GetOctetOutputStream(m_bufferSize);

                // TODO[cms] bc-java appears to support some sort of digest-only authentication here
                IMac mac = MacUtilities.GetMac(macAlgId.Algorithm);
                // TODO Confirm no ParametersWithRandom needed
                mac.Init(cipherParameters);
                Stream mOut = new TeeOutputStream(ecStream, new MacSink(mac));

                return new CmsAuthenticatedDataOutputStream(mOut, mac, cGen, authGen, eciGen, ecGen);
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
         */
        public Stream Open(Stream outStr, string encryptionOid)
        {
            CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

            keyGen.Init(new KeyGenerationParameters(m_random, keyGen.DefaultStrength));

            return Open(outStr, encryptionOid, keyGen);
        }

        /**
         * generate an enveloped object that contains an CMS Enveloped Data object
         */
        public Stream Open(Stream outStr, string encryptionOid, int keySize)
        {
            CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

            keyGen.Init(new KeyGenerationParameters(m_random, keySize));

            return Open(outStr, encryptionOid, keyGen);
        }

        private class CmsAuthenticatedDataOutputStream
            : BaseOutputStream
        {
            private readonly Stream m_macStream;
            private readonly IMac m_mac;
            private readonly BerSequenceGenerator m_cGen;
            private readonly BerSequenceGenerator m_authGen;
            private readonly BerSequenceGenerator m_eciGen;
            private readonly BerOctetStringGenerator m_ecGen;

            public CmsAuthenticatedDataOutputStream(Stream macStream, IMac mac, BerSequenceGenerator cGen,
                BerSequenceGenerator authGen, BerSequenceGenerator eciGen, BerOctetStringGenerator ecGen)
            {
                m_macStream = macStream;
                m_mac = mac;
                m_cGen = cGen;
                m_authGen = authGen;
                m_eciGen = eciGen;
                m_ecGen = ecGen;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                m_macStream.Write(buffer, offset, count);
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void Write(ReadOnlySpan<byte> buffer)
            {
                m_macStream.Write(buffer);
            }
#endif

            public override void WriteByte(byte value)
            {
                m_macStream.WriteByte(value);
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    m_macStream.Dispose();

                    // TODO Parent context(s) should really be be closed explicitly

                    m_ecGen.Dispose();
                    m_eciGen.Dispose();

                    // [TODO] auth attributes go here 
                    m_authGen.AddObject(DerOctetString.WithContents(MacUtilities.DoFinal(m_mac)));
                    // [TODO] unauth attributes go here

                    m_authGen.Dispose();
                    m_cGen.Dispose();
                }
                base.Dispose(disposing);
            }
        }
    }
}
