using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Cms.Ecc;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms
{
	internal class KeyAgreeRecipientInfoGenerator
		: RecipientInfoGenerator
	{
		private static readonly CmsEnvelopedHelper Helper = CmsEnvelopedHelper.Instance;

        private readonly List<KeyAgreeRecipientIdentifier> m_recipientIDs = new List<KeyAgreeRecipientIdentifier>();
        private readonly List<AsymmetricKeyParameter> m_recipientKeys = new List<AsymmetricKeyParameter>();

        private DerObjectIdentifier m_keyAgreementOid;
		private DerObjectIdentifier m_keyEncryptionOid;
		private AsymmetricCipherKeyPair m_senderKeyPair;

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

		public RecipientInfo Generate(KeyParameter contentEncryptionKey, SecureRandom random)
		{
			byte[] keyBytes = contentEncryptionKey.GetKey();

			AsymmetricKeyParameter senderPublicKey = m_senderKeyPair.Public;
			ICipherParameters senderPrivateParams = m_senderKeyPair.Private;

			OriginatorIdentifierOrKey originator;
			try
			{
				originator = new OriginatorIdentifierOrKey(
					CreateOriginatorPublicKey(senderPublicKey));
			}
			catch (IOException e)
			{
				throw new InvalidKeyException("cannot extract originator public key: " + e);
			}

			Asn1OctetString ukm = null;
            if (CmsUtilities.IsMqv(m_keyAgreementOid))
			{
				try
				{
					IAsymmetricCipherKeyPairGenerator ephemKPG =
						GeneratorUtilities.GetKeyPairGenerator(m_keyAgreementOid);
					ephemKPG.Init(
						((ECPublicKeyParameters)senderPublicKey).CreateKeyGenerationParameters(random));

					AsymmetricCipherKeyPair ephemKP = ephemKPG.GenerateKeyPair();

					ukm = new DerOctetString(
						new MQVuserKeyingMaterial(
							CreateOriginatorPublicKey(ephemKP.Public), null));

					senderPrivateParams = new MqvPrivateParameters(
						(ECPrivateKeyParameters)senderPrivateParams,
						(ECPrivateKeyParameters)ephemKP.Private,
						(ECPublicKeyParameters)ephemKP.Public);
				}
				catch (IOException e)
				{
					throw new InvalidKeyException("cannot extract MQV ephemeral public key: " + e);
				}
				catch (SecurityUtilityException e)
				{
					throw new InvalidKeyException("cannot determine MQV ephemeral key pair parameters from public key: " + e);
				}
			}

			DerSequence paramSeq = new DerSequence(m_keyEncryptionOid, DerNull.Instance);
			AlgorithmIdentifier keyEncAlg = new AlgorithmIdentifier(m_keyAgreementOid, paramSeq);

			Asn1EncodableVector recipientEncryptedKeys = new Asn1EncodableVector(m_recipientIDs.Count);
            for (int i = 0; i < m_recipientIDs.Count; ++i)
			{
				var recipientID = m_recipientIDs[i];
				ICipherParameters recipientPublicParams = m_recipientKeys[i];

				if (m_keyAgreementOid.Id.Equals(CmsEnvelopedGenerator.ECMqvSha1Kdf))
				{
					recipientPublicParams = new MqvPublicParameters(
						(ECPublicKeyParameters)recipientPublicParams,
						(ECPublicKeyParameters)recipientPublicParams);
				}

				// Use key agreement to choose a wrap key for this recipient
				IBasicAgreement keyAgreement = AgreementUtilities.GetBasicAgreementWithKdf(
					m_keyAgreementOid, m_keyEncryptionOid);
				keyAgreement.Init(new ParametersWithRandom(senderPrivateParams, random));
				BigInteger agreedValue = keyAgreement.CalculateAgreement(recipientPublicParams);

				int keyEncryptionKeySize = GeneratorUtilities.GetDefaultKeySize(m_keyEncryptionOid) / 8;
				byte[] keyEncryptionKeyBytes = X9IntegerConverter.IntegerToBytes(agreedValue, keyEncryptionKeySize);
				KeyParameter keyEncryptionKey = ParameterUtilities.CreateKeyParameter(
					m_keyEncryptionOid, keyEncryptionKeyBytes);

				// Wrap the content encryption key with the agreement key
				IWrapper keyWrapper = WrapperUtilities.GetWrapper(m_keyEncryptionOid.Id);
				keyWrapper.Init(true, new ParametersWithRandom(keyEncryptionKey, random));
				byte[] encryptedKeyBytes = keyWrapper.Wrap(keyBytes, 0, keyBytes.Length);

	        	Asn1OctetString encryptedKey = new DerOctetString(encryptedKeyBytes);

				recipientEncryptedKeys.Add(new RecipientEncryptedKey(recipientID, encryptedKey));
			}

			return new RecipientInfo(new KeyAgreeRecipientInfo(originator, ukm, keyEncAlg,
				new DerSequence(recipientEncryptedKeys)));
		}

		private static OriginatorPublicKey CreateOriginatorPublicKey(AsymmetricKeyParameter publicKey) =>
			CreateOriginatorPublicKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey));

        private static OriginatorPublicKey CreateOriginatorPublicKey(SubjectPublicKeyInfo originatorKeyInfo) =>
			new OriginatorPublicKey(originatorKeyInfo.Algorithm, originatorKeyInfo.PublicKey);
    }
}
