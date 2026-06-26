using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    /**
     * General class for generating a CMS enveloped-data message.
     *
     * A simple example of usage.
     *
     * <pre>
     *      CMSEnvelopedDataGenerator  fact = new CMSEnvelopedDataGenerator();
     *
     *      fact.addKeyTransRecipient(cert);
     *
     *      CMSEnvelopedData         data = fact.generate(content, algorithm, "BC");
     * </pre>
     */
    public abstract class CmsEnvelopedGenerator
    {
        public static readonly string DesCbc = OiwObjectIdentifiers.DesCbc.Id;
        public static readonly string DesEde3Cbc = PkcsObjectIdentifiers.DesEde3Cbc.Id;
        public static readonly string RC2Cbc = PkcsObjectIdentifiers.RC2Cbc.Id;
        // TODO[api] Change to static readonly
        public const string IdeaCbc = "1.3.6.1.4.1.188.7.1.1.2";
        //public static readonly string IdeaCbc           = MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC.Id;
        // TODO[api] Change to static readonly
        public const string Cast5Cbc = "1.2.840.113533.7.66.10";
        //public static readonly string CastCbc           = MiscObjectIdentifiers.cast5CBC.Id;
        public static readonly string Aes128Cbc = NistObjectIdentifiers.IdAes128Cbc.Id;
        public static readonly string Aes192Cbc = NistObjectIdentifiers.IdAes192Cbc.Id;
        public static readonly string Aes256Cbc = NistObjectIdentifiers.IdAes256Cbc.Id;
        public static readonly string Aes128Ccm = NistObjectIdentifiers.IdAes128Ccm.Id;
        public static readonly string Aes192Ccm = NistObjectIdentifiers.IdAes192Ccm.Id;
        public static readonly string Aes256Ccm = NistObjectIdentifiers.IdAes256Ccm.Id;
        public static readonly string Aes128Gcm = NistObjectIdentifiers.IdAes128Gcm.Id;
        public static readonly string Aes192Gcm = NistObjectIdentifiers.IdAes192Gcm.Id;
        public static readonly string Aes256Gcm = NistObjectIdentifiers.IdAes256Gcm.Id;
        public static readonly string Camellia128Cbc = NttObjectIdentifiers.IdCamellia128Cbc.Id;
        public static readonly string Camellia192Cbc = NttObjectIdentifiers.IdCamellia192Cbc.Id;
        public static readonly string Camellia256Cbc = NttObjectIdentifiers.IdCamellia256Cbc.Id;
        public static readonly string SeedCbc = KisaObjectIdentifiers.IdSeedCbc.Id;

        public static readonly string DesEde3Wrap = PkcsObjectIdentifiers.IdAlgCms3DesWrap.Id;
        public static readonly string Aes128Wrap = NistObjectIdentifiers.IdAes128Wrap.Id;
        public static readonly string Aes192Wrap = NistObjectIdentifiers.IdAes192Wrap.Id;
        public static readonly string Aes256Wrap = NistObjectIdentifiers.IdAes256Wrap.Id;
        public static readonly string Camellia128Wrap = NttObjectIdentifiers.IdCamellia128Wrap.Id;
        public static readonly string Camellia192Wrap = NttObjectIdentifiers.IdCamellia192Wrap.Id;
        public static readonly string Camellia256Wrap = NttObjectIdentifiers.IdCamellia256Wrap.Id;
        public static readonly string SeedWrap = KisaObjectIdentifiers.IdNpkiAppCmsSeedWrap.Id;

        public static readonly string Gost28147Wrap = CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap.Id;
        public static readonly string Gost28147CryptoProWrap = CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap.Id;

        public static readonly string ECDHSha1Kdf = X9ObjectIdentifiers.DHSinglePassStdDHSha1KdfScheme.Id;
        public static readonly string ECCDHSha1Kdf = X9ObjectIdentifiers.DHSinglePassCofactorDHSha1KdfScheme.Id;
        public static readonly string ECMqvSha1Kdf = X9ObjectIdentifiers.MqvSinglePassSha1KdfScheme.Id;

        public static readonly string ECDHSha224Kdf = SecObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme.Id;
        public static readonly string ECCDHSha224Kdf = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme.Id;
        public static readonly string ECMqvSha224Kdf = SecObjectIdentifiers.mqvSinglePass_sha224kdf_scheme.Id;

        public static readonly string ECDHSha256Kdf = SecObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme.Id;
        public static readonly string ECCDHSha256Kdf = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme.Id;
        public static readonly string ECMqvSha256Kdf = SecObjectIdentifiers.mqvSinglePass_sha256kdf_scheme.Id;

        public static readonly string ECDHSha384Kdf = SecObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme.Id;
        public static readonly string ECCDHSha384Kdf = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme.Id;
        public static readonly string ECMqvSha384Kdf = SecObjectIdentifiers.mqvSinglePass_sha384kdf_scheme.Id;

        public static readonly string ECDHSha512Kdf = SecObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme.Id;
        public static readonly string ECCDHSha512Kdf = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme.Id;
        public static readonly string ECMqvSha512Kdf = SecObjectIdentifiers.mqvSinglePass_sha512kdf_scheme.Id;

        internal readonly List<RecipientInfoGenerator> recipientInfoGenerators = new List<RecipientInfoGenerator>();
        internal readonly SecureRandom m_random;

        internal CmsAttributeTableGenerator unprotectedAttributeGenerator = null;

        internal OriginatorInformation m_originatorInformation = null;

        protected CmsEnvelopedGenerator()
            : this(CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        protected CmsEnvelopedGenerator(SecureRandom random)
        {
            if (random == null)
                throw new ArgumentNullException(nameof(random));

            m_random = random;
        }

        public CmsAttributeTableGenerator UnprotectedAttributeGenerator
        {
            get { return this.unprotectedAttributeGenerator; }
            set { this.unprotectedAttributeGenerator = value; }
        }

        public OriginatorInformation OriginatorInformation
        {
            get { return m_originatorInformation; }
            set { m_originatorInformation = value; }
        }

        /**
         * add a recipient.
         *
         * @param cert recipient's public key certificate
         * @exception ArgumentException if there is a problem with the certificate
         */
        public void AddKeyTransRecipient(X509Certificate cert)
        {
            var algorithm = cert.SubjectPublicKeyInfo.Algorithm;
            var keyWrapper = new Asn1KeyWrapper(algorithm, cert);
            AddRecipientInfoGenerator(new KeyTransRecipientInfoGenerator(cert, keyWrapper));
        }

        /**
         * add a recipient.
         *
         * @param algorithm to override automatic selection (useful for OAEP with PKCS#1v1.5 certs)
         * @param cert recipient's public key certificate
         * @exception ArgumentException if there is a problem with the certificate
         */
        public void AddKeyTransRecipient(string algorithm, X509Certificate cert)
        {
            var keyWrapper = new Asn1KeyWrapper(algorithm, cert);
            AddRecipientInfoGenerator(new KeyTransRecipientInfoGenerator(cert, keyWrapper));
        }

        /**
         * add a recipient
         *
         * @param key the public key used by the recipient
         * @param subKeyId the identifier for the recipient's public key
         * @exception ArgumentException if there is a problem with the key
         */
        public void AddKeyTransRecipient(AsymmetricKeyParameter pubKey, byte[] subKeyId)
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);
            AddRecipientInfoGenerator(
                new KeyTransRecipientInfoGenerator(subKeyId, new Asn1KeyWrapper(info.Algorithm, pubKey)));
        }

        /**
         * add a recipient
         *
         * @param algorithm to override automatic selection (useful for OAEP with PKCS#1v1.5 certs)
         * @param key the public key used by the recipient
         * @param subKeyId the identifier for the recipient's public key
         * @exception ArgumentException if there is a problem with the key
         */
        public void AddKeyTransRecipient(string algorithm, AsymmetricKeyParameter pubKey, byte[] subKeyId)
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);
            AddRecipientInfoGenerator(
                new KeyTransRecipientInfoGenerator(subKeyId, new Asn1KeyWrapper(algorithm, pubKey)));
        }

        /**
         * add a KEK recipient.
         * @param key the secret key to use for wrapping
         * @param keyIdentifier the byte string that identifies the key
         */
        public void AddKekRecipient(
            string keyAlgorithm, // TODO Remove need for this parameter
            KeyParameter key,
            byte[] keyIdentifier)
        {
            AddKekRecipient(keyAlgorithm, key, new KekIdentifier(keyIdentifier, null, null));
        }

        /**
         * add a KEK recipient.
         * @param key the secret key to use for wrapping
         * @param keyIdentifier the byte string that identifies the key
         */
        public void AddKekRecipient(
            string keyAlgorithm, // TODO Remove need for this parameter
            KeyParameter key,
            KekIdentifier kekIdentifier)
        {
            KekRecipientInfoGenerator kekrig = new KekRecipientInfoGenerator();
            kekrig.KekIdentifier = kekIdentifier;
            kekrig.KeyEncryptionKeyOID = keyAlgorithm;
            kekrig.KeyEncryptionKey = key;

            recipientInfoGenerators.Add(kekrig);
        }

        public void AddPasswordRecipient(
            CmsPbeKey pbeKey,
            string kekAlgorithmOid)
        {
            Pbkdf2Params p = new Pbkdf2Params(pbeKey.Salt, pbeKey.IterationCount);

            PasswordRecipientInfoGenerator prig = new PasswordRecipientInfoGenerator();
            prig.KeyDerivationAlgorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbkdf2, p);
            prig.KeyEncryptionKeyOID = kekAlgorithmOid;
            prig.KeyEncryptionKey = pbeKey.GetEncoded(kekAlgorithmOid);

            recipientInfoGenerators.Add(prig);
        }

        /**
         * Add a key agreement based recipient.
         *
         * @param agreementAlgorithm key agreement algorithm to use.
         * @param senderPrivateKey private key to initialise sender side of agreement with.
         * @param senderPublicKey sender public key to include with message.
         * @param recipientCert recipient's public key certificate.
         * @param cekWrapAlgorithm OID for key wrapping algorithm to use.
         * @exception SecurityUtilityException if the algorithm requested cannot be found
         * @exception InvalidKeyException if the keys are inappropriate for the algorithm specified
         */
        public void AddKeyAgreementRecipient(
            string agreementAlgorithm,
            AsymmetricKeyParameter senderPrivateKey,
            AsymmetricKeyParameter senderPublicKey,
            X509Certificate recipientCert,
            string cekWrapAlgorithm)
        {
            var recipientCerts = new List<X509Certificate>(1) { recipientCert };

            AddKeyAgreementRecipients(agreementAlgorithm, senderPrivateKey, senderPublicKey, recipientCerts,
                cekWrapAlgorithm);
        }

        /**
         * Add multiple key agreement based recipients (sharing a single KeyAgreeRecipientInfo structure).
         *
         * @param agreementAlgorithm key agreement algorithm to use.
         * @param senderPrivateKey private key to initialise sender side of agreement with.
         * @param senderPublicKey sender public key to include with message.
         * @param recipientCerts recipients' public key certificates.
         * @param cekWrapAlgorithm OID for key wrapping algorithm to use.
         * @exception SecurityUtilityException if the algorithm requested cannot be found
         * @exception InvalidKeyException if the keys are inappropriate for the algorithm specified
         */
        public void AddKeyAgreementRecipients(
            string agreementAlgorithm,
            AsymmetricKeyParameter senderPrivateKey,
            AsymmetricKeyParameter senderPublicKey,
            IEnumerable<X509Certificate> recipientCerts,
            string cekWrapAlgorithm)
        {
            if (!senderPrivateKey.IsPrivate)
                throw new ArgumentException("Expected private key", nameof(senderPrivateKey));
            if (senderPublicKey.IsPrivate)
                throw new ArgumentException("Expected public key", nameof(senderPublicKey));

            /* TODO
             * "a recipient X.509 version 3 certificate that contains a key usage extension MUST
             * assert the keyAgreement bit."
             */

            recipientInfoGenerators.Add(new KeyAgreeRecipientInfoGenerator(recipientCerts)
            {
                KeyAgreementOid = new DerObjectIdentifier(agreementAlgorithm),
                KeyEncryptionOid = new DerObjectIdentifier(cekWrapAlgorithm),
                SenderKeyPair = new AsymmetricCipherKeyPair(senderPublicKey, senderPrivateKey),
            });
        }

        public void AddKeyAgreementRecipient(
            string agreementAlgorithm,
            AsymmetricKeyParameter senderPrivateKey,
            AsymmetricKeyParameter senderPublicKey,
            byte[] recipientKeyID,
            AsymmetricKeyParameter recipientPublicKey,
            string cekWrapAlgorithm)
        {
            if (!senderPrivateKey.IsPrivate)
                throw new ArgumentException("Expected private key", nameof(senderPrivateKey));
            if (senderPublicKey.IsPrivate)
                throw new ArgumentException("Expected public key", nameof(senderPublicKey));
            if (recipientPublicKey.IsPrivate)
                throw new ArgumentException("Expected public key", nameof(recipientPublicKey));

            recipientInfoGenerators.Add(new KeyAgreeRecipientInfoGenerator(recipientKeyID, recipientPublicKey)
            {
                KeyAgreementOid = new DerObjectIdentifier(agreementAlgorithm),
                KeyEncryptionOid = new DerObjectIdentifier(cekWrapAlgorithm),
                SenderKeyPair = new AsymmetricCipherKeyPair(senderPublicKey, senderPrivateKey),
            });
        }

        /// <summary>
        /// Add a generator to produce the recipient info required.
        /// </summary>
        /// <param name="recipientInfoGenerator">a generator of a recipient info object.</param>
	    public void AddRecipientInfoGenerator(RecipientInfoGenerator recipientInfoGenerator)
        {
            recipientInfoGenerators.Add(recipientInfoGenerator);
        }

        protected internal virtual AlgorithmIdentifier GetAlgorithmIdentifier(string encryptionOid,
            KeyParameter encKey, Asn1Encodable asn1Params, out ICipherParameters cipherParameters)
        {
            Asn1Object asn1Object;
            if (asn1Params != null)
            {
                asn1Object = asn1Params.ToAsn1Object();
                cipherParameters = ParameterUtilities.GetCipherParameters(encryptionOid, encKey, asn1Object);
            }
            else
            {
                // TODO[cms] Should this be NoParams depending on the encryption algorithm?
                asn1Object = DerNull.Instance;
                cipherParameters = encKey;
            }

            return new AlgorithmIdentifier(new DerObjectIdentifier(encryptionOid), asn1Object);
        }

        protected internal virtual Asn1Encodable GenerateAsn1Parameters(string encryptionOid, byte[] encKeyBytes)
        {
            Asn1Encodable asn1Params = null;

            try
            {
                if (encryptionOid.Equals(RC2Cbc))
                {
                    byte[] iv = new byte[8];
                    m_random.NextBytes(iv);

                    int effectiveKeyBits = encKeyBytes.Length * 8;
                    int parameterVersion = RC2CbcUtilities.GetParameterVersion(effectiveKeyBits);

                    asn1Params = new RC2CbcParameter(parameterVersion, iv);
                }
                else
                {
                    asn1Params = ParameterUtilities.GenerateParameters(encryptionOid, m_random);
                }
            }
            catch (SecurityUtilityException)
            {
                // No problem... no parameters generated
            }

            return asn1Params;
        }
    }
}
