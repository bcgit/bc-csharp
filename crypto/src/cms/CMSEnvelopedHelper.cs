using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    internal class CmsEnvelopedHelper
    {
        private static readonly Dictionary<string, int> FixedKeySizes = new Dictionary<string, int>();
        private static readonly Dictionary<string, string> Rfc3211WrapperNames = new Dictionary<string, string>();

        static CmsEnvelopedHelper()
        {
            FixedKeySizes.Add(CmsEnvelopedGenerator.Aes128Cbc, 128);
            FixedKeySizes.Add(CmsEnvelopedGenerator.Aes192Cbc, 192);
            FixedKeySizes.Add(CmsEnvelopedGenerator.Aes256Cbc, 256);
            FixedKeySizes.Add(CmsEnvelopedGenerator.Aes128Ccm, 128);
            FixedKeySizes.Add(CmsEnvelopedGenerator.Aes192Ccm, 192);
            FixedKeySizes.Add(CmsEnvelopedGenerator.Aes256Ccm, 256);
            FixedKeySizes.Add(CmsEnvelopedGenerator.Aes128Gcm, 128);
            FixedKeySizes.Add(CmsEnvelopedGenerator.Aes192Gcm, 192);
            FixedKeySizes.Add(CmsEnvelopedGenerator.Aes256Gcm, 256);
            FixedKeySizes.Add(CmsEnvelopedGenerator.Camellia128Cbc, 128);
            FixedKeySizes.Add(CmsEnvelopedGenerator.Camellia192Cbc, 192);
            FixedKeySizes.Add(CmsEnvelopedGenerator.Camellia256Cbc, 256);
            FixedKeySizes.Add(CmsEnvelopedGenerator.DesCbc, 64);
            FixedKeySizes.Add(CmsEnvelopedGenerator.DesEde3Cbc, 192);
            FixedKeySizes.Add(CmsEnvelopedGenerator.IdeaCbc, 128);
            FixedKeySizes.Add(CmsEnvelopedGenerator.SeedCbc, 128);

            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Aes128Cbc, "AESRFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Aes192Cbc, "AESRFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Aes256Cbc, "AESRFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Camellia128Cbc, "CAMELLIARFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Camellia192Cbc, "CAMELLIARFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.Camellia256Cbc, "CAMELLIARFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.DesCbc, "DESRFC3211WRAP");
            Rfc3211WrapperNames.Add(CmsEnvelopedGenerator.DesEde3Cbc, "DESEDERFC3211WRAP");
        }

        internal static RecipientInformationStore BuildRecipientInformationStore(Asn1Set recipientInfos,
            CmsSecureReadable secureReadable)
        {
            var infos = new List<RecipientInformation>();
            for (int i = 0; i != recipientInfos.Count; i++)
            {
                RecipientInfo info = RecipientInfo.GetInstance(recipientInfos[i]);

                ReadRecipientInfo(infos, info, secureReadable);
            }
            return new RecipientInformationStore(infos);
        }

        internal static int GetKeySize(string oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (!FixedKeySizes.TryGetValue(oid, out var keySize))
                throw new ArgumentException("no key size for " + oid, nameof(oid));

            return keySize;
        }

        internal static string GetRfc3211WrapperName(string oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (!Rfc3211WrapperNames.TryGetValue(oid, out var name))
                throw new ArgumentException("no name for " + oid, nameof(oid));

            return name;
        }

        private static void ReadRecipientInfo(IList<RecipientInformation> infos, RecipientInfo info,
            CmsSecureReadable secureReadable)
        {
            Asn1Encodable recipInfo = info.Info;
            if (recipInfo is KeyTransRecipientInfo keyTransRecipientInfo)
            {
                infos.Add(new KeyTransRecipientInformation(keyTransRecipientInfo, secureReadable));
            }
            else if (recipInfo is KekRecipientInfo kekRecipientInfo)
            {
                infos.Add(new KekRecipientInformation(kekRecipientInfo, secureReadable));
            }
            else if (recipInfo is KeyAgreeRecipientInfo keyAgreeRecipientInfo)
            {
                KeyAgreeRecipientInformation.ReadRecipientInfo(infos, keyAgreeRecipientInfo, secureReadable);
            }
            else if (recipInfo is PasswordRecipientInfo passwordRecipientInfo)
            {
                infos.Add(new PasswordRecipientInformation(passwordRecipientInfo, secureReadable));
            }
        }

        internal class CmsAuthenticatedSecureReadable
            : CmsSecureReadable
        {
            private AlgorithmIdentifier algorithm;
            private IMac mac;
            private CmsReadable readable;

            internal CmsAuthenticatedSecureReadable(AlgorithmIdentifier algorithm, CmsReadable readable)
            {
                this.algorithm = algorithm;
                this.readable = readable;
            }

            public AlgorithmIdentifier Algorithm => this.algorithm;

            public object CryptoObject => this.mac;

            public CmsReadable GetReadable(KeyParameter sKey)
            {
                string macAlg = this.algorithm.Algorithm.Id;
                //Asn1Object sParams = this.algorithm.Parameters.ToAsn1Object();

                try
                {
                    this.mac = MacUtilities.GetMac(macAlg);

                    // FIXME Support for MAC algorithm parameters similar to cipher parameters
                    //ASN1Object sParams = (ASN1Object)macAlg.getParameters();

                    //if (X509Utilities.IsAbsentParameters(sParams))
                    {
                        mac.Init(sKey);
                    }
                    //else
                    //{
                    //    AlgorithmParameters params = CMSEnvelopedHelper.INSTANCE.createAlgorithmParameters(macAlg.getObjectId().getId(), provider);
                    //        params.init(sParams.getEncoded(), "ASN.1");
                    //    mac.init(sKey, params.getParameterSpec(IvParameterSpec.class));
                    //}

                    //Asn1Object asn1Params = asn1Enc?.ToAsn1Object();

                    //ICipherParameters cipherParameters = sKey;

                    //if (X509Utilities.IsAbsentParameters(asn1Params))
                    //{
                    //    var algOid = macAlg.Algorithm;

                    //    if (PkcsObjectIdentifiers.DesEde3Cbc.Equals(algOid) ||
                    //        MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC.Equals(algOid) ||
                    //        MiscObjectIdentifiers.cast5CBC.Equals(algOid))
                    //    {
                    //        cipherParameters = new ParametersWithIV(cipherParameters, new byte[8]);
                    //    }
                    //}
                    //else
                    //{
                    //    cipherParameters = ParameterUtilities.GetCipherParameters(macAlg.Algorithm, cipherParameters,
                    //        asn1Params);
                    //}

                    //mac.Init(cipherParameters);
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
                    throw new CmsException("error decoding algorithm parameters.", e);
                }

                try
                {
                    return new CmsProcessableInputStream(
                        new TeeInputStream(
                            readable.GetInputStream(),
                            new MacSink(this.mac)));
                }
                catch (IOException e)
                {
                    throw new CmsException("error reading content.", e);
                }
            }
        }

        internal class CmsEnvelopedSecureReadable
            : CmsSecureReadable
        {
            private readonly AlgorithmIdentifier m_algorithm;
            private readonly CmsReadable m_readable;

            private IBufferedCipher m_cipher;

            internal CmsEnvelopedSecureReadable(AlgorithmIdentifier algorithm, CmsReadable readable)
            {
                m_algorithm = algorithm;
                m_readable = readable;
            }

            public AlgorithmIdentifier Algorithm => m_algorithm;

            public object CryptoObject => m_cipher;

            public CmsReadable GetReadable(KeyParameter sKey)
            {
                try
                {
                    m_cipher = CipherUtilities.GetCipher(m_algorithm.Algorithm);

                    Asn1Object asn1Params = m_algorithm.Parameters?.ToAsn1Object();

                    ICipherParameters cipherParameters = sKey;

                    if (X509Utilities.IsAbsentParameters(asn1Params))
                    {
                        var algOid = m_algorithm.Algorithm;

                        if (PkcsObjectIdentifiers.DesEde3Cbc.Equals(algOid) ||
                            MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC.Equals(algOid) ||
                            MiscObjectIdentifiers.cast5CBC.Equals(algOid))
                        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                            cipherParameters = ParametersWithIV.Create<byte>(cipherParameters, 8, 0,
                                (bytes, state) => bytes.Fill(state));
#else
                            cipherParameters = new ParametersWithIV(cipherParameters, new byte[8]);
#endif
                        }
                    }
                    else
                    {
                        cipherParameters = ParameterUtilities.GetCipherParameters(m_algorithm.Algorithm,
                            cipherParameters, asn1Params);
                    }

                    m_cipher.Init(forEncryption: false, cipherParameters);
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
                    throw new CmsException("error decoding algorithm parameters.", e);
                }

                try
                {
                    return new CmsProcessableInputStream(
                        new CipherStream(m_readable.GetInputStream(), m_cipher, null));
                }
                catch (IOException e)
                {
                    throw new CmsException("error reading content.", e);
                }
            }
        }
    }
}
