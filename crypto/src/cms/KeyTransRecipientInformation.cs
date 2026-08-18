using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// CMS recipient information for key transport, where the content-encryption key is encrypted for a recipient's
    /// public key.
    /// </summary>
    public class KeyTransRecipientInformation
        : RecipientInformation
    {
        private readonly KeyTransRecipientInfo m_info;

        internal KeyTransRecipientInformation(KeyTransRecipientInfo info, CmsSecureReadable secureReadable)
            : base(info.KeyEncryptionAlgorithm, secureReadable)
        {
            this.rid = new RecipientID();

            m_info = info;

            RecipientIdentifier r = info.RecipientIdentifier;

            try
            {
                if (r.IsTagged)
                {
                    var subjectKeyIdentifier = SubjectKeyIdentifier.GetInstance(r.ID);

                    rid.SubjectKeyIdentifier = subjectKeyIdentifier.GetEncoded(Asn1Encodable.Der);
                }
                else
                {
                    var issuerAndSerialNumber = IssuerAndSerialNumber.GetInstance(r.ID);

                    rid.Issuer = issuerAndSerialNumber.Issuer;
                    rid.SerialNumber = issuerAndSerialNumber.SerialNumber.Value;
                }
            }
            catch (IOException)
            {
                throw new ArgumentException("invalid rid in KeyTransRecipientInformation");
            }
        }

        private string GetExchangeEncryptionAlgorithmName(AlgorithmIdentifier algID)
        {
            var algOid = algID.Algorithm;

            if (Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Equals(algOid))
            {
                return "RSA//PKCS1Padding";
            }
            else if (Asn1.Pkcs.PkcsObjectIdentifiers.IdRsaesOaep.Equals(algOid))
            {
                var rsaesOaepParameters = Asn1.Pkcs.RsaesOaepParameters.GetInstance(algID.Parameters);
                var digestName = DigestUtilities.GetAlgorithmName(rsaesOaepParameters.HashAlgorithm.Algorithm);
                return "RSA//OAEPWITH" + digestName + "ANDMGF1Padding";
            }

            return algOid.GetID();
        }

        internal KeyParameter UnwrapKey(ICipherParameters key)
        {
            byte[] encryptedKey = m_info.EncryptedKey.GetOctets();

            try
            {
                string contentAlgorithmName = GetContentAlgorithmName();

                if (Asn1.Pkcs.PkcsObjectIdentifiers.RsaEncryption.Equals(keyEncAlg.Algorithm))
                {
                    if (GeneratorUtilities.TryGetFixedKeySize(contentAlgorithmName, out int fixedKeySizeBits) &&
                        (fixedKeySizeBits & 7) == 0)
                    {
                        int fixedLength = fixedKeySizeBits / 8;

                        var rsaKeyParameters = (RsaKeyParameters)ParameterUtilities.GetRandom(key, out var providedRandom);
                        var secureRandom = CryptoServicesRegistrar.GetSecureRandom(providedRandom);

                        byte[] keyBytes = RsaPkcs1Utilities.DecryptToFixedLength(fixedLength, encryptedKey, 0,
                            encryptedKey.Length, rsaKeyParameters, secureRandom);

                        return ParameterUtilities.CreateKeyParameter(contentAlgorithmName, keyBytes);
                    }

                    // The legacy unwrap provides a Bleichenbacher padding Oracle, so require user intervention to allow
                    if (Properties.GetBoolean(Properties.CmsAllowLenientRsaPkcs1, false))
                    {
                        IKeyUnwrapper keyWrapper = new Asn1KeyUnwrapper(keyEncAlg.Algorithm, keyEncAlg.Parameters, key);
                        byte[] keyBytes = keyWrapper.Unwrap(encryptedKey, 0, encryptedKey.Length).Collect();
                        return ParameterUtilities.CreateKeyParameter(contentAlgorithmName, keyBytes);
                    }

                    throw new CmsException("no fixed size for content-encryption key; constant-time RSA unwrap unavailable.");
                }

                if (Asn1.Pkcs.PkcsObjectIdentifiers.IdRsaesOaep.Equals(keyEncAlg.Algorithm))
                {
                    IKeyUnwrapper keyWrapper = new Asn1KeyUnwrapper(keyEncAlg.Algorithm, keyEncAlg.Parameters, key);
                    byte[] keyBytes = keyWrapper.Unwrap(encryptedKey, 0, encryptedKey.Length).Collect();
                    return ParameterUtilities.CreateKeyParameter(contentAlgorithmName, keyBytes);
                }

                {
                    string keyExchangeAlgorithm = GetExchangeEncryptionAlgorithmName(keyEncAlg);
                    IWrapper keyWrapper = WrapperUtilities.GetWrapper(keyExchangeAlgorithm);
                    keyWrapper.Init(forWrapping: false, key);
                    byte[] keyBytes = keyWrapper.Unwrap(encryptedKey, 0, encryptedKey.Length);

                    // FIXME Support for MAC algorithm parameters similar to cipher parameters
                    return ParameterUtilities.CreateKeyParameter(contentAlgorithmName, keyBytes);
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
            catch (DataLengthException e)
            {
                throw new CmsException("illegal blocksize in message.", e);
            }
            catch (InvalidCipherTextException e)
            {
                throw new CmsException("bad padding in message.", e);
            }
        }

        /// <summary>Decrypts the content using the recipient's private key and returns a stream over it.</summary>
        /// <param name="key">The recipient's private key.</param>
        /// <returns>A typed stream over the decrypted content.</returns>
        /// <exception cref="CmsException">Thrown if the content-encryption key cannot be recovered.</exception>
        public override CmsTypedStream GetContentStream(ICipherParameters key) => GetContentFromSessionKey(UnwrapKey(key));
    }
}
