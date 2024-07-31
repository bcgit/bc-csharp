using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Cms.Ecc;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cms
{
    /**
    * the RecipientInfo class for a recipient who has been sent a message
    * encrypted using key agreement.
    */
    public class KeyAgreeRecipientInformation
        : RecipientInformation
    {
        private readonly KeyAgreeRecipientInfo m_info;
        private readonly Asn1OctetString m_encryptedKey;

        internal static void ReadRecipientInfo(IList<RecipientInformation> infos, KeyAgreeRecipientInfo info,
            CmsSecureReadable secureReadable)
        {
            try
            {
                foreach (Asn1Encodable rek in info.RecipientEncryptedKeys)
                {
                    RecipientEncryptedKey id = RecipientEncryptedKey.GetInstance(rek.ToAsn1Object());

                    RecipientID rid = new RecipientID();

                    Asn1.Cms.KeyAgreeRecipientIdentifier karid = id.Identifier;

                    Asn1.Cms.IssuerAndSerialNumber iAndSN = karid.IssuerAndSerialNumber;
                    if (iAndSN != null)
                    {
                        rid.Issuer = iAndSN.Name;
                        rid.SerialNumber = iAndSN.SerialNumber.Value;
                    }
                    else
                    {
                        Asn1.Cms.RecipientKeyIdentifier rKeyID = karid.RKeyID;

                        // Note: 'date' and 'other' fields of RecipientKeyIdentifier appear to be only informational 

                        rid.SubjectKeyIdentifier = rKeyID.SubjectKeyIdentifier.GetEncoded(Asn1Encodable.Der);
                    }

                    infos.Add(new KeyAgreeRecipientInformation(info, rid, id.EncryptedKey,
                        secureReadable));
                }
            }
            catch (IOException e)
            {
                throw new ArgumentException("invalid rid in KeyAgreeRecipientInformation", e);
            }
        }

        internal KeyAgreeRecipientInformation(KeyAgreeRecipientInfo info, RecipientID rid, Asn1OctetString encryptedKey,
            CmsSecureReadable secureReadable)
            : base(info.KeyEncryptionAlgorithm, secureReadable)
        {
            m_info = info;
            this.rid = rid;
            m_encryptedKey = encryptedKey;
        }

        private AsymmetricKeyParameter GetSenderPublicKey(AsymmetricKeyParameter receiverPrivateKey,
            OriginatorIdentifierOrKey originator)
        {
            OriginatorPublicKey opk = originator.OriginatorPublicKey;
            if (opk != null)
                return GetPublicKeyFromOriginatorPublicKey(receiverPrivateKey, opk);

            OriginatorID origID = new OriginatorID();

            Asn1.Cms.IssuerAndSerialNumber iAndSN = originator.IssuerAndSerialNumber;
            if (iAndSN != null)
            {
                origID.Issuer = iAndSN.Name;
                origID.SerialNumber = iAndSN.SerialNumber.Value;
            }
            else
            {
                SubjectKeyIdentifier ski = originator.SubjectKeyIdentifier;

                origID.SubjectKeyIdentifier = ski.GetEncoded(Asn1Encodable.Der);
            }

            return GetPublicKeyFromOriginatorID(origID);
        }

        private AsymmetricKeyParameter GetPublicKeyFromOriginatorPublicKey(AsymmetricKeyParameter receiverPrivateKey,
            OriginatorPublicKey originatorPublicKey)
        {
            PrivateKeyInfo privInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(receiverPrivateKey);
            SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(privInfo.PrivateKeyAlgorithm,
                originatorPublicKey.PublicKey);
            return PublicKeyFactory.CreateKey(pubInfo);
        }

        private AsymmetricKeyParameter GetPublicKeyFromOriginatorID(
            OriginatorID origID)
        {
            // TODO Support all alternatives for OriginatorIdentifierOrKey
            // see RFC 3852 6.2.2
            throw new CmsException("No support for 'originator' as IssuerAndSerialNumber or SubjectKeyIdentifier");
        }

        private KeyParameter CalculateAgreedWrapKey(DerObjectIdentifier wrapAlgOid,
            AsymmetricKeyParameter senderPublicKey, AsymmetricKeyParameter receiverPrivateKey)
        {
            DerObjectIdentifier agreeAlgID = keyEncAlg.Algorithm;

            ICipherParameters senderPublicParams = senderPublicKey;
            ICipherParameters receiverPrivateParams = receiverPrivateKey;

            if (agreeAlgID.Id.Equals(CmsEnvelopedGenerator.ECMqvSha1Kdf))
            {
                byte[] ukmEncoding = m_info.UserKeyingMaterial.GetOctets();
                MQVuserKeyingMaterial ukm = MQVuserKeyingMaterial.GetInstance(
                    Asn1Object.FromByteArray(ukmEncoding));

                AsymmetricKeyParameter ephemeralKey = GetPublicKeyFromOriginatorPublicKey(
                    receiverPrivateKey, ukm.EphemeralPublicKey);

                senderPublicParams = new MqvPublicParameters(
                    (ECPublicKeyParameters)senderPublicParams,
                    (ECPublicKeyParameters)ephemeralKey);
                receiverPrivateParams = new MqvPrivateParameters(
                    (ECPrivateKeyParameters)receiverPrivateParams,
                    (ECPrivateKeyParameters)receiverPrivateParams);
            }

            IBasicAgreement agreement = AgreementUtilities.GetBasicAgreementWithKdf(agreeAlgID, wrapAlgOid);
            agreement.Init(receiverPrivateParams);
            BigInteger agreedValue = agreement.CalculateAgreement(senderPublicParams);

            int wrapKeySize = GeneratorUtilities.GetDefaultKeySize(wrapAlgOid) / 8;
            byte[] wrapKeyBytes = X9IntegerConverter.IntegerToBytes(agreedValue, wrapKeySize);
            return ParameterUtilities.CreateKeyParameter(wrapAlgOid, wrapKeyBytes);
        }

        private KeyParameter UnwrapSessionKey(DerObjectIdentifier wrapAlgOid, KeyParameter agreedKey)
        {
            byte[] encKeyOctets = m_encryptedKey.GetOctets();

            IWrapper keyCipher = WrapperUtilities.GetWrapper(wrapAlgOid);
            keyCipher.Init(false, agreedKey);
            byte[] sKeyBytes = keyCipher.Unwrap(encKeyOctets, 0, encKeyOctets.Length);
            return ParameterUtilities.CreateKeyParameter(GetContentAlgorithmName(), sKeyBytes);
        }

        internal KeyParameter GetSessionKey(AsymmetricKeyParameter receiverPrivateKey)
        {
            try
            {
                var wrapAlgOid = DerObjectIdentifier.GetInstance(Asn1Sequence.GetInstance(keyEncAlg.Parameters)[0]);

                AsymmetricKeyParameter senderPublicKey = GetSenderPublicKey(receiverPrivateKey, m_info.Originator);

                KeyParameter agreedWrapKey = CalculateAgreedWrapKey(wrapAlgOid, senderPublicKey, receiverPrivateKey);

                if (CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap.Equals(wrapAlgOid) ||
                    CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap.Equals(wrapAlgOid))
                {
                    // TODO[cms] GOST key wrapping
                }

                return UnwrapSessionKey(wrapAlgOid, agreedWrapKey);
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("couldn't create cipher.", e);
            }
            catch (InvalidKeyException e)
            {
                throw new CmsException("key invalid in message.", e);
            }
            catch (Exception e)
            {
                throw new CmsException("originator key invalid.", e);
            }
        }

        /**
        * decrypt the content and return an input stream.
        */
        public override CmsTypedStream GetContentStream(
            ICipherParameters key)
        {
            if (!(key is AsymmetricKeyParameter receiverPrivateKey))
                throw new ArgumentException("KeyAgreement requires asymmetric key", "key");

            if (!receiverPrivateKey.IsPrivate)
                throw new ArgumentException("Expected private key", "key");

            KeyParameter sKey = GetSessionKey(receiverPrivateKey);

            return GetContentFromSessionKey(sKey);
        }
    }
}
