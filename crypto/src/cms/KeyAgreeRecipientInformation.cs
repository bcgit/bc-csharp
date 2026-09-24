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
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// CMS recipient information for key agreement, where a sender and recipient derive the key-encryption key.
    /// </summary>
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
                foreach (Asn1Encodable element in info.RecipientEncryptedKeys)
                {
                    RecipientEncryptedKey id = RecipientEncryptedKey.GetInstance(element);
                    Asn1.Cms.KeyAgreeRecipientIdentifier karid = id.Identifier;
                    Asn1.Cms.IssuerAndSerialNumber iAndSN = karid.IssuerAndSerialNumber;

                    RecipientID rid = new RecipientID();
                    if (iAndSN != null)
                    {
                        rid.Issuer = iAndSN.Issuer;
                        rid.SerialNumber = iAndSN.SerialNumber.Value;
                    }
                    else
                    {
                        // Note: 'date' and 'other' fields of RecipientKeyIdentifier appear to be only informational

                        rid.SubjectKeyIdentifier = karid.RKeyID.SubjectKeyIdentifier.GetEncoded(Asn1Encodable.Der);
                    }

                    infos.Add(new KeyAgreeRecipientInformation(info, rid, id.EncryptedKey, secureReadable));
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
            OriginatorPublicKey originatorKey = originator.OriginatorKey;
            if (originatorKey != null)
                return GetPublicKeyFromOriginatorPublicKey(receiverPrivateKey, originatorKey);

            OriginatorID origID = new OriginatorID();

            Asn1.Cms.IssuerAndSerialNumber issuerAndSerialNumber = originator.IssuerAndSerialNumber;
            if (issuerAndSerialNumber != null)
            {
                origID.Issuer = issuerAndSerialNumber.Issuer;
                origID.SerialNumber = issuerAndSerialNumber.SerialNumber.Value;
            }
            else
            {
                origID.SubjectKeyIdentifier = originator.SubjectKeyIdentifier.GetEncoded(Asn1Encodable.Der);
            }

            return GetPublicKeyFromOriginatorID(origID);
        }

        private static AsymmetricKeyParameter GetPublicKeyFromOriginatorPublicKey(AsymmetricKeyParameter receiverPrivateKey,
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

        private static KeyParameter CalculateAgreedWrapKey(DerObjectIdentifier agreeAlgOid,
            AlgorithmIdentifier wrapAlgID, AsymmetricKeyParameter senderPublicKey, Asn1OctetString userKeyingMaterial,
            AsymmetricKeyParameter receiverPrivateKey)
        {
            ICipherParameters senderPublicParams = senderPublicKey;
            ICipherParameters receiverPrivateParams = receiverPrivateKey;

            // RFC 8418 sec. 2.2: for the HKDF schemes a ukm is both the entityUInfo of the
            // ECC-CMS-SharedInfo and the HKDF salt
            if (userKeyingMaterial != null && CmsUtilities.IsHkdf(agreeAlgOid))
            {
                // TODO[cms] Add HKDF support, with some way to handle UKM
                throw new NotImplementedException();
            }

            if (CmsUtilities.IsMqv(agreeAlgOid))
            {
                MQVuserKeyingMaterial ukm = MQVuserKeyingMaterial.GetInstance(userKeyingMaterial.GetOctets());

                AsymmetricKeyParameter ephemeralKey = GetPublicKeyFromOriginatorPublicKey(
                    receiverPrivateKey, ukm.EphemeralPublicKey);

                senderPublicParams = new MqvPublicParameters(
                    (ECPublicKeyParameters)senderPublicParams,
                    (ECPublicKeyParameters)ephemeralKey);
                receiverPrivateParams = new MqvPrivateParameters(
                    (ECPrivateKeyParameters)receiverPrivateParams,
                    (ECPrivateKeyParameters)receiverPrivateParams);
            }
            else
            {
                // TODO[cms] bc-java has other consumers of userKeyingMaterial in EC, GOST, RFC2631 branches
            }

            IBasicAgreement agreement = AgreementUtilities.GetBasicAgreementWithKdf(agreeAlgOid, wrapAlgID);
            agreement.Init(receiverPrivateParams);
            BigInteger agreedValue = agreement.CalculateAgreement(senderPublicParams);

            DerObjectIdentifier wrapAlgOid = wrapAlgID.Algorithm;
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
                AlgorithmIdentifier wrapAlgID = AlgorithmIdentifier.GetInstance(keyEncAlg.Parameters);

                AsymmetricKeyParameter senderPublicKey = GetSenderPublicKey(receiverPrivateKey, m_info.Originator);

                DerObjectIdentifier agreeAlgOid = keyEncAlg.Algorithm;
                DerObjectIdentifier wrapAlgOid = wrapAlgID.Algorithm;

                KeyParameter agreedWrapKey = CalculateAgreedWrapKey(agreeAlgOid, wrapAlgID, senderPublicKey,
                    m_info.UserKeyingMaterial, receiverPrivateKey);

                if (CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap.Equals(wrapAlgOid) ||
                    CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap.Equals(wrapAlgOid))
                {
                    // TODO[cms] GOST key wrapping
                }

                try
                {
                    return UnwrapSessionKey(wrapAlgOid, agreedWrapKey);
                }
                catch (InvalidCipherTextException)
                    when (wrapAlgID.Parameters == null &&
                          Properties.GetBoolean(Properties.CmsAllowLegacyKeyAgreeKdf, true))
                {
                    /*
                     * bc-csharp until 2.7.0 derived the KEK as though the key-wrap AlgorithmIdentifier carried NULL
                     * parameters, even when it was encoded with absent parameters (github bc-csharp #697). Retry with
                     * that derivation so that messages from those versions remain readable.
                     */
                    // TODO[api] Consider defaulting CmsAllowLegacyKeyAgreeKdf to false (or removing the retry)
                    try
                    {
                        var legacyWrapAlgID = new AlgorithmIdentifier(wrapAlgOid, DerNull.Instance);

                        KeyParameter legacyWrapKey = CalculateAgreedWrapKey(agreeAlgOid, legacyWrapAlgID,
                            senderPublicKey, m_info.UserKeyingMaterial, receiverPrivateKey);

                        return UnwrapSessionKey(wrapAlgOid, legacyWrapKey);
                    }
                    catch (Exception)
                    {
                        // Ignore any exception during the retry
                    }

                    // Re-throw original InvalidCipherTextException
                    throw;
                }
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("couldn't create cipher.", e);
            }
            catch (InvalidKeyException e)
            {
                throw new CmsException("key invalid in message.", e);
            }
            catch (CmsException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new CmsException("originator key invalid.", e);
            }
        }

        /// <summary>Decrypts the content using the recipient's key-agreement private key.</summary>
        /// <param name="key">The recipient's private asymmetric key.</param>
        /// <returns>A typed stream over the decrypted content.</returns>
        /// <exception cref="ArgumentException">Thrown if <paramref name="key"/> is not a private asymmetric key.
        /// </exception>
        /// <exception cref="CmsException">Thrown if key agreement or content-key recovery fails.</exception>
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
