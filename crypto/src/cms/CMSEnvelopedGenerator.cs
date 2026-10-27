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
    /// <summary>General class for generating a CMS enveloped-data message.</summary>
    /// <remarks>
    /// Add one or more recipients, then use the generator of a specific message type to produce the message.
    /// </remarks>
    public abstract class CmsEnvelopedGenerator
    {
        /// <summary>The object identifier (as a string) of the DES in CBC mode content encryption algorithm.</summary>
        public static readonly string DesCbc = OiwObjectIdentifiers.DesCbc.Id;
        /// <summary>
        /// The object identifier (as a string) of the triple DES in CBC mode content encryption algorithm.
        /// </summary>
        public static readonly string DesEde3Cbc = PkcsObjectIdentifiers.DesEde3Cbc.Id;
        /// <summary>The object identifier (as a string) of the RC2 in CBC mode content encryption algorithm.</summary>
        public static readonly string RC2Cbc = PkcsObjectIdentifiers.RC2Cbc.Id;
        // TODO[api] Change to static readonly
        /// <summary>The object identifier (as a string) of the IDEA in CBC mode content encryption algorithm.</summary>
        public const string IdeaCbc = "1.3.6.1.4.1.188.7.1.1.2";
        //public static readonly string IdeaCbc           = MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC.Id;
        // TODO[api] Change to static readonly
        /// <summary>
        /// The object identifier (as a string) of the CAST5 in CBC mode content encryption algorithm.
        /// </summary>
        public const string Cast5Cbc = "1.2.840.113533.7.66.10";
        //public static readonly string CastCbc           = MiscObjectIdentifiers.cast5CBC.Id;
        /// <summary>
        /// The object identifier (as a string) of the AES-128 in CBC mode content encryption algorithm.
        /// </summary>
        public static readonly string Aes128Cbc = NistObjectIdentifiers.IdAes128Cbc.Id;
        /// <summary>
        /// The object identifier (as a string) of the AES-192 in CBC mode content encryption algorithm.
        /// </summary>
        public static readonly string Aes192Cbc = NistObjectIdentifiers.IdAes192Cbc.Id;
        /// <summary>
        /// The object identifier (as a string) of the AES-256 in CBC mode content encryption algorithm.
        /// </summary>
        public static readonly string Aes256Cbc = NistObjectIdentifiers.IdAes256Cbc.Id;
        /// <summary>
        /// The object identifier (as a string) of the AES-128 in CCM mode content encryption algorithm.
        /// </summary>
        public static readonly string Aes128Ccm = NistObjectIdentifiers.IdAes128Ccm.Id;
        /// <summary>
        /// The object identifier (as a string) of the AES-192 in CCM mode content encryption algorithm.
        /// </summary>
        public static readonly string Aes192Ccm = NistObjectIdentifiers.IdAes192Ccm.Id;
        /// <summary>
        /// The object identifier (as a string) of the AES-256 in CCM mode content encryption algorithm.
        /// </summary>
        public static readonly string Aes256Ccm = NistObjectIdentifiers.IdAes256Ccm.Id;
        /// <summary>
        /// The object identifier (as a string) of the AES-128 in GCM mode content encryption algorithm.
        /// </summary>
        public static readonly string Aes128Gcm = NistObjectIdentifiers.IdAes128Gcm.Id;
        /// <summary>
        /// The object identifier (as a string) of the AES-192 in GCM mode content encryption algorithm.
        /// </summary>
        public static readonly string Aes192Gcm = NistObjectIdentifiers.IdAes192Gcm.Id;
        /// <summary>
        /// The object identifier (as a string) of the AES-256 in GCM mode content encryption algorithm.
        /// </summary>
        public static readonly string Aes256Gcm = NistObjectIdentifiers.IdAes256Gcm.Id;
        /// <summary>
        /// The object identifier (as a string) of the Camellia-128 in CBC mode content encryption algorithm.
        /// </summary>
        public static readonly string Camellia128Cbc = NttObjectIdentifiers.IdCamellia128Cbc.Id;
        /// <summary>
        /// The object identifier (as a string) of the Camellia-192 in CBC mode content encryption algorithm.
        /// </summary>
        public static readonly string Camellia192Cbc = NttObjectIdentifiers.IdCamellia192Cbc.Id;
        /// <summary>
        /// The object identifier (as a string) of the Camellia-256 in CBC mode content encryption algorithm.
        /// </summary>
        public static readonly string Camellia256Cbc = NttObjectIdentifiers.IdCamellia256Cbc.Id;
        /// <summary>The object identifier (as a string) of the SEED in CBC mode content encryption algorithm.</summary>
        public static readonly string SeedCbc = KisaObjectIdentifiers.IdSeedCbc.Id;

        /// <summary>The object identifier (as a string) of the triple DES key wrap algorithm.</summary>
        public static readonly string DesEde3Wrap = PkcsObjectIdentifiers.IdAlgCms3DesWrap.Id;
        /// <summary>The object identifier (as a string) of the AES-128 key wrap algorithm.</summary>
        public static readonly string Aes128Wrap = NistObjectIdentifiers.IdAes128Wrap.Id;
        /// <summary>The object identifier (as a string) of the AES-192 key wrap algorithm.</summary>
        public static readonly string Aes192Wrap = NistObjectIdentifiers.IdAes192Wrap.Id;
        /// <summary>The object identifier (as a string) of the AES-256 key wrap algorithm.</summary>
        public static readonly string Aes256Wrap = NistObjectIdentifiers.IdAes256Wrap.Id;
        /// <summary>The object identifier (as a string) of the Camellia-128 key wrap algorithm.</summary>
        public static readonly string Camellia128Wrap = NttObjectIdentifiers.IdCamellia128Wrap.Id;
        /// <summary>The object identifier (as a string) of the Camellia-192 key wrap algorithm.</summary>
        public static readonly string Camellia192Wrap = NttObjectIdentifiers.IdCamellia192Wrap.Id;
        /// <summary>The object identifier (as a string) of the Camellia-256 key wrap algorithm.</summary>
        public static readonly string Camellia256Wrap = NttObjectIdentifiers.IdCamellia256Wrap.Id;
        /// <summary>The object identifier (as a string) of the SEED key wrap algorithm.</summary>
        public static readonly string SeedWrap = KisaObjectIdentifiers.IdNpkiAppCmsSeedWrap.Id;

        /// <summary>The object identifier (as a string) of the GOST 28147-89 key wrap algorithm.</summary>
        public static readonly string Gost28147Wrap = CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap.Id;
        /// <summary>The object identifier (as a string) of the GOST 28147-89 CryptoPro key wrap algorithm.</summary>
        public static readonly string Gost28147CryptoProWrap = CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap.Id;

        /// <summary>
        /// The object identifier (as a string) of the ephemeral-static ECDH with a SHA-1 KDF key agreement scheme.
        /// </summary>
        public static readonly string ECDHSha1Kdf = X9ObjectIdentifiers.DHSinglePassStdDHSha1KdfScheme.Id;
        /// <summary>
        /// The object identifier (as a string) of the cofactor ECDH with a SHA-1 KDF key agreement scheme.
        /// </summary>
        public static readonly string ECCDHSha1Kdf = X9ObjectIdentifiers.DHSinglePassCofactorDHSha1KdfScheme.Id;
        /// <summary>The object identifier (as a string) of the ECMQV with a SHA-1 KDF key agreement scheme.</summary>
        public static readonly string ECMqvSha1Kdf = X9ObjectIdentifiers.MqvSinglePassSha1KdfScheme.Id;

        /// <summary>The object identifier (as a string) of the ECDH with a SHA-224 KDF key agreement scheme.</summary>
        public static readonly string ECDHSha224Kdf = SecObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme.Id;
        /// <summary>
        /// The object identifier (as a string) of the cofactor ECDH with a SHA-224 KDF key agreement scheme.
        /// </summary>
        public static readonly string ECCDHSha224Kdf = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme.Id;
        /// <summary>The object identifier (as a string) of the ECMQV with a SHA-224 KDF key agreement scheme.</summary>
        public static readonly string ECMqvSha224Kdf = SecObjectIdentifiers.mqvSinglePass_sha224kdf_scheme.Id;

        /// <summary>The object identifier (as a string) of the ECDH with a SHA-256 KDF key agreement scheme.</summary>
        public static readonly string ECDHSha256Kdf = SecObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme.Id;
        /// <summary>
        /// The object identifier (as a string) of the cofactor ECDH with a SHA-256 KDF key agreement scheme.
        /// </summary>
        public static readonly string ECCDHSha256Kdf = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme.Id;
        /// <summary>The object identifier (as a string) of the ECMQV with a SHA-256 KDF key agreement scheme.</summary>
        public static readonly string ECMqvSha256Kdf = SecObjectIdentifiers.mqvSinglePass_sha256kdf_scheme.Id;

        /// <summary>The object identifier (as a string) of the ECDH with a SHA-384 KDF key agreement scheme.</summary>
        public static readonly string ECDHSha384Kdf = SecObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme.Id;
        /// <summary>
        /// The object identifier (as a string) of the cofactor ECDH with a SHA-384 KDF key agreement scheme.
        /// </summary>
        public static readonly string ECCDHSha384Kdf = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme.Id;
        /// <summary>The object identifier (as a string) of the ECMQV with a SHA-384 KDF key agreement scheme.</summary>
        public static readonly string ECMqvSha384Kdf = SecObjectIdentifiers.mqvSinglePass_sha384kdf_scheme.Id;

        /// <summary>The object identifier (as a string) of the ECDH with a SHA-512 KDF key agreement scheme.</summary>
        public static readonly string ECDHSha512Kdf = SecObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme.Id;
        /// <summary>
        /// The object identifier (as a string) of the cofactor ECDH with a SHA-512 KDF key agreement scheme.
        /// </summary>
        public static readonly string ECCDHSha512Kdf = SecObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme.Id;
        /// <summary>The object identifier (as a string) of the ECMQV with a SHA-512 KDF key agreement scheme.</summary>
        public static readonly string ECMqvSha512Kdf = SecObjectIdentifiers.mqvSinglePass_sha512kdf_scheme.Id;

        internal readonly List<RecipientInfoGenerator> recipientInfoGenerators = new List<RecipientInfoGenerator>();
        internal readonly SecureRandom m_random;

        internal CmsAttributeTableGenerator unprotectedAttributeGenerator = null;

        internal OriginatorInformation m_originatorInformation = null;

        // TODO[api] Restrict to internal
        /// <summary>Create a generator using the default source of randomness.</summary>
        protected CmsEnvelopedGenerator()
            : this(CryptoServicesRegistrar.GetSecureRandom())
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        // TODO[api] Restrict to internal
        protected CmsEnvelopedGenerator(SecureRandom random)
        {
            if (random == null)
                throw new ArgumentNullException(nameof(random));

            m_random = random;
        }

        /// <summary>Gets or sets the generator for the unprotected attributes.</summary>
        public CmsAttributeTableGenerator UnprotectedAttributeGenerator
        {
            get { return this.unprotectedAttributeGenerator; }
            set { this.unprotectedAttributeGenerator = value; }
        }

        /// <summary>Gets or sets the originator information to include, or null for none.</summary>
        public OriginatorInformation OriginatorInformation
        {
            get { return m_originatorInformation; }
            set { m_originatorInformation = value; }
        }

        /// <summary>Add a recipient.</summary>
        /// <param name="cert">The recipient's public key certificate.</param>
        /// <exception cref="ArgumentException">There is a problem with the certificate.</exception>
        public void AddKeyTransRecipient(X509Certificate cert)
        {
            var algorithm = cert.SubjectPublicKeyInfo.Algorithm;
            var keyWrapper = new Asn1KeyWrapper(algorithm, cert);
            AddRecipientInfoGenerator(new KeyTransRecipientInfoGenerator(cert, keyWrapper));
        }

        /// <summary>Add a recipient.</summary>
        /// <param name="algorithm">
        /// The algorithm, to override automatic selection (useful for OAEP with PKCS#1v1.5 certs).
        /// </param>
        /// <param name="cert">The recipient's public key certificate.</param>
        /// <exception cref="ArgumentException">There is a problem with the certificate.</exception>
        public void AddKeyTransRecipient(string algorithm, X509Certificate cert)
        {
            var keyWrapper = new Asn1KeyWrapper(algorithm, cert);
            AddRecipientInfoGenerator(new KeyTransRecipientInfoGenerator(cert, keyWrapper));
        }

        /// <summary>Add a recipient.</summary>
        /// <param name="pubKey">The public key used by the recipient.</param>
        /// <param name="subKeyId">The identifier for the recipient's public key.</param>
        /// <exception cref="ArgumentException">There is a problem with the key.</exception>
        public void AddKeyTransRecipient(AsymmetricKeyParameter pubKey, byte[] subKeyId)
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);
            AddRecipientInfoGenerator(
                new KeyTransRecipientInfoGenerator(subKeyId, new Asn1KeyWrapper(info.Algorithm, pubKey)));
        }

        /// <summary>Add a recipient.</summary>
        /// <param name="algorithm">The algorithm, to override automatic selection (useful for OAEP with PKCS#1v1.5
        /// certs).</param>
        /// <param name="pubKey">The public key used by the recipient.</param>
        /// <param name="subKeyId">The identifier for the recipient's public key.</param>
        /// <exception cref="ArgumentException">There is a problem with the key.</exception>
        public void AddKeyTransRecipient(string algorithm, AsymmetricKeyParameter pubKey, byte[] subKeyId)
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);
            AddRecipientInfoGenerator(
                new KeyTransRecipientInfoGenerator(subKeyId, new Asn1KeyWrapper(algorithm, pubKey)));
        }

        /// <summary>Add a KEK recipient.</summary>
        /// <param name="keyAlgorithm">The algorithm of the key encryption key.</param>
        /// <param name="key">The secret key to use for wrapping.</param>
        /// <param name="keyIdentifier">The byte string that identifies the key.</param>
        public void AddKekRecipient(
            string keyAlgorithm, // TODO Remove need for this parameter
            KeyParameter key,
            byte[] keyIdentifier)
        {
            AddKekRecipient(keyAlgorithm, key, new KekIdentifier(keyIdentifier, null, null));
        }

        /// <summary>Add a KEK recipient.</summary>
        /// <param name="keyAlgorithm">The algorithm of the key encryption key.</param>
        /// <param name="key">The secret key to use for wrapping.</param>
        /// <param name="kekIdentifier">The identifier of the key.</param>
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

        /// <summary>Add a password based recipient.</summary>
        /// <param name="pbeKey">The password based key.</param>
        /// <param name="kekAlgorithmOid">The object identifier of the key encryption algorithm.</param>
        public void AddPasswordRecipient(CmsPbeKey pbeKey, string kekAlgorithmOid)
        {
            if (pbeKey == null)
                throw new ArgumentNullException(nameof(pbeKey));
            if (kekAlgorithmOid == null)
                throw new ArgumentNullException(nameof(kekAlgorithmOid));
            if (!DerObjectIdentifier.TryFromID(kekAlgorithmOid, out var kekAlgOid))
                throw new ArgumentException("Must be an OID string", nameof(kekAlgorithmOid));

            Pbkdf2Params p = new Pbkdf2Params(pbeKey.Salt, pbeKey.IterationCount);

            PasswordRecipientInfoGenerator prig = new PasswordRecipientInfoGenerator();
            prig.KeyDerivationAlgorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbkdf2, p);
            prig.KeyEncryptionKeyOID = kekAlgorithmOid;
            prig.KeyEncryptionKey = pbeKey.GetEncoded(kekAlgOid);

            recipientInfoGenerators.Add(prig);
        }

        /// <summary>Add a key agreement based recipient.</summary>
        /// <param name="agreementAlgorithm">key agreement algorithm to use.</param>
        /// <param name="senderPrivateKey">private key to initialise sender side of agreement with.</param>
        /// <param name="senderPublicKey">sender public key to include with message.</param>
        /// <param name="recipientCert">recipient's public key certificate.</param>
        /// <param name="cekWrapAlgorithm">OID for key wrapping algorithm to use.</param>
        /// <exception cref="SecurityUtilityException">if the algorithm requested cannot be found</exception>
        /// <exception cref="InvalidKeyException">if the keys are inappropriate for the algorithm specified</exception>
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

        /// <summary>
        /// Add multiple key agreement based recipients (sharing a single KeyAgreeRecipientInfo structure).
        /// </summary>
        /// <param name="agreementAlgorithm">key agreement algorithm to use.</param>
        /// <param name="senderPrivateKey">private key to initialise sender side of agreement with.</param>
        /// <param name="senderPublicKey">sender public key to include with message.</param>
        /// <param name="recipientCerts">recipients' public key certificates.</param>
        /// <param name="cekWrapAlgorithm">OID for key wrapping algorithm to use.</param>
        /// <exception cref="SecurityUtilityException">if the algorithm requested cannot be found</exception>
        /// <exception cref="InvalidKeyException">if the keys are inappropriate for the algorithm specified</exception>
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

        /// <summary>Add a key agreement based recipient identified by a key identifier.</summary>
        /// <param name="agreementAlgorithm">The key agreement algorithm to use.</param>
        /// <param name="senderPrivateKey">The private key to initialise the sender side of the agreement with.</param>
        /// <param name="senderPublicKey">The sender public key to include with the message.</param>
        /// <param name="recipientKeyID">The identifier of the recipient's public key.</param>
        /// <param name="recipientPublicKey">The recipient's public key.</param>
        /// <param name="cekWrapAlgorithm">The object identifier of the key wrapping algorithm to use.</param>
        /// <exception cref="ArgumentException">A key is of the wrong kind (private or public).</exception>
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

        /// <summary>Generate the ASN.1 parameters for the given encryption algorithm.</summary>
        /// <param name="encryptionOid">The encryption algorithm's object identifier.</param>
        /// <param name="encKeyBytes">The encryption key.</param>
        [Obsolete("Will be removed")]
        protected internal virtual Asn1Encodable GenerateAsn1Parameters(string encryptionOid, byte[] encKeyBytes) =>
            Asn1CipherBuilderWithKey.ImplGenerateAsn1Parameters(m_random, encryptionOid, encKeyBytes);

        /// <summary>Return the algorithm identifier for the given encryption algorithm.</summary>
        /// <param name="encryptionOid">The encryption algorithm's object identifier.</param>
        /// <param name="encKey">The encryption key.</param>
        /// <param name="asn1Params">The ASN.1 algorithm parameters.</param>
        /// <param name="cipherParameters">The cipher parameters to use with the algorithm.</param>
        [Obsolete("Will be removed")]
        protected internal virtual AlgorithmIdentifier GetAlgorithmIdentifier(string encryptionOid,
            KeyParameter encKey, Asn1Encodable asn1Params, out ICipherParameters cipherParameters)
        {
            return Asn1CipherBuilderWithKey.ImplGetAlgorithmIdentifier(encryptionOid, encKey, asn1Params,
                out cipherParameters);
        }
    }
}
