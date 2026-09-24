using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Cms.Ecc;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
    internal class KeyAgreeRecipientInfoGenerator
        : RecipientInfoGenerator
    {
        private readonly List<KeyAgreeRecipientIdentifier> m_recipientIDs = new List<KeyAgreeRecipientIdentifier>();
        private readonly List<AsymmetricKeyParameter> m_recipientKeys = new List<AsymmetricKeyParameter>();

        private DerObjectIdentifier m_keyAgreementOid;
        private DerObjectIdentifier m_keyEncryptionOid;
        private AsymmetricCipherKeyPair m_senderKeyPair;

        private byte[] m_userKeyingMaterial;

        internal KeyAgreeRecipientInfoGenerator(IEnumerable<X509Certificate> recipientCerts)
        {
            foreach (var recipientCert in recipientCerts)
            {
                m_recipientIDs.Add(new KeyAgreeRecipientIdentifier(CmsUtilities.GetIssuerAndSerialNumber(recipientCert)));
                m_recipientKeys.Add(recipientCert.GetPublicKey());
            }
        }

        internal KeyAgreeRecipientInfoGenerator(byte[] subjectKeyID, AsymmetricKeyParameter publicKey)
        {
            m_recipientIDs.Add(new KeyAgreeRecipientIdentifier(new RecipientKeyIdentifier(subjectKeyID)));
            m_recipientKeys.Add(publicKey);
        }

        internal DerObjectIdentifier KeyAgreementOid
        {
            set { m_keyAgreementOid = value; }
        }

        internal DerObjectIdentifier KeyEncryptionOid
        {
            set { m_keyEncryptionOid = value; }
        }

        internal AsymmetricCipherKeyPair SenderKeyPair
        {
            set { m_senderKeyPair = value; }
        }

        // TODO[cms] Support public configuration of this
        internal byte[] UserKeyingMaterial
        {
            set { m_userKeyingMaterial = Arrays.Clone(value); }
        }

        public RecipientInfo Generate(KeyParameter contentEncryptionKey, SecureRandom random)
        {
            random = CryptoServicesRegistrar.GetSecureRandom(random);

            byte[] keyBytes = contentEncryptionKey.GetKey();

            AsymmetricKeyParameter senderPublicKey = m_senderKeyPair.Public;
            ICipherParameters senderPrivateParams = m_senderKeyPair.Private;

            OriginatorIdentifierOrKey originator;
            try
            {
                var originatorKey = CreateOriginatorPublicKey(senderPublicKey);
                originator = new OriginatorIdentifierOrKey(originatorKey);
            }
            catch (IOException e)
            {
                throw new InvalidKeyException("cannot extract originator public key: " + e);
            }

            Asn1Encodable keyEncAlgParams = null;
            if (CmsUtilities.IsDes(m_keyEncryptionOid) || PkcsObjectIdentifiers.IdAlgCmsRC2Wrap.Equals(m_keyEncryptionOid))
            {
                keyEncAlgParams = DerNull.Instance;
            }
            //else if (CmsUtilities.IsGost(m_keyAgreementOid))
            //{
            //    keyEncAlgParams = new Gost2814789KeyWrapParameters(CryptoProObjectIdentifiers.ID_Gost28147_89_CryptoPro_A_ParamSet);
            //}

            if (m_recipientIDs.Count < 1)
                throw new CmsException("No recipients associated with generator");

            var kdfUkm = m_userKeyingMaterial;

            // RFC 3370 sec. 4.1.2 (static-static DH) and RFC 4490 sec. 4.1.1 (GOST): the ukm MUST be present
            // TODO Consider delegating to an OID classifier for static-key agreement schemes
            if (kdfUkm == null &&
                (PkcsObjectIdentifiers.IdAlgSsdh.Equals(m_keyAgreementOid) || CmsUtilities.IsGost(m_keyAgreementOid)))
            {
                throw new CmsException("User keying material must be set for static keys.");
            }

            // RFC 8418 sec. 2.2: for the HKDF schemes a ukm is both the entityUInfo of the
            // ECC-CMS-SharedInfo and the HKDF salt
            if (kdfUkm != null && CmsUtilities.IsHkdf(m_keyAgreementOid))
            {
                // TODO[cms] Add HKDF support, with some way to handle UKM
                throw new NotImplementedException();
            }

            AlgorithmIdentifier keyEncAlgorithm = new AlgorithmIdentifier(m_keyEncryptionOid, keyEncAlgParams);
            AlgorithmIdentifier keyAgreeAlgorithm = new AlgorithmIdentifier(m_keyAgreementOid, keyEncAlgorithm);

            bool isMqv = CmsUtilities.IsMqv(m_keyAgreementOid);

            AsymmetricCipherKeyPair ephemeralKeyPair = null;
            Asn1OctetString ukm = DerOctetString.WithContentsOptional(kdfUkm);

            if (isMqv)
            {
                try
                {
                    var kpg = GeneratorUtilities.GetKeyPairGenerator(m_keyAgreementOid);
                    kpg.Init(((ECPublicKeyParameters)senderPublicKey).CreateKeyGenerationParameters(random));
                    ephemeralKeyPair = kpg.GenerateKeyPair();

                    var ephemeralPublicKey = CreateOriginatorPublicKey(ephemeralKeyPair.Public);
                    var mqvUkm = new MQVuserKeyingMaterial(ephemeralPublicKey, addedukm: ukm);

                    // The MQVuserKeyingMaterial is sent DER-encoded in KeyAgreeRecipientInfo.ukm
                    ukm = new DerOctetString(mqvUkm);

                    senderPrivateParams = new MqvPrivateParameters(
                        (ECPrivateKeyParameters)senderPrivateParams,
                        (ECPrivateKeyParameters)ephemeralKeyPair.Private,
                        (ECPublicKeyParameters)ephemeralKeyPair.Public);
                }
                catch (Exception e)
                {
                    throw new InvalidKeyException("cannot determine MQV ephemeral key pair parameters from public key: " + e);
                }
            }

            senderPrivateParams = ParameterUtilities.WithUkm(senderPrivateParams, kdfUkm);
            senderPrivateParams = ParameterUtilities.WithRandom(senderPrivateParams, random);

            Asn1EncodableVector recipientEncryptedKeys = new Asn1EncodableVector(m_recipientIDs.Count);
            for (int i = 0; i < m_recipientIDs.Count; ++i)
            {
                var recipientID = m_recipientIDs[i];
                ICipherParameters recipientPublicParams = m_recipientKeys[i];

                if (isMqv)
                {
                    // NOTE: recipient public key used in both static and ephemeral roles
                    recipientPublicParams = new MqvPublicParameters(
                        (ECPublicKeyParameters)recipientPublicParams,
                        (ECPublicKeyParameters)recipientPublicParams);
                }

                // Use key agreement to choose a wrap key for this recipient
                IBasicAgreement keyAgreement = AgreementUtilities.GetBasicAgreementWithKdf(m_keyAgreementOid,
                    keyEncAlgorithm);
                keyAgreement.Init(senderPrivateParams);
                BigInteger agreedValue = keyAgreement.CalculateAgreement(recipientPublicParams);

                int keyEncryptionKeySize = GeneratorUtilities.GetDefaultKeySize(m_keyEncryptionOid) / 8;
                byte[] keyEncryptionKeyBytes = X9IntegerConverter.IntegerToBytes(agreedValue, keyEncryptionKeySize);
                KeyParameter keyEncryptionKey = ParameterUtilities.CreateKeyParameter(
                    m_keyEncryptionOid, keyEncryptionKeyBytes);

                // Wrap the content encryption key with the agreement key
                IWrapper keyWrapper = WrapperUtilities.GetWrapper(m_keyEncryptionOid);
                keyWrapper.Init(forWrapping: true, new ParametersWithRandom(keyEncryptionKey, random));
                byte[] encryptedKeyBytes = keyWrapper.Wrap(keyBytes, 0, keyBytes.Length);

                Asn1OctetString encryptedKey = new DerOctetString(encryptedKeyBytes);

                recipientEncryptedKeys.Add(new RecipientEncryptedKey(recipientID, encryptedKey));
            }

            return new RecipientInfo(
                new KeyAgreeRecipientInfo(originator, ukm, keyAgreeAlgorithm,
                    DerSequence.FromVector(recipientEncryptedKeys)));
        }

        private static OriginatorPublicKey CreateOriginatorPublicKey(AsymmetricKeyParameter publicKey) =>
            CreateOriginatorPublicKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey));

        private static OriginatorPublicKey CreateOriginatorPublicKey(SubjectPublicKeyInfo originatorKeyInfo) =>
            new OriginatorPublicKey(originatorKeyInfo.Algorithm, originatorKeyInfo.PublicKey);
    }
}
