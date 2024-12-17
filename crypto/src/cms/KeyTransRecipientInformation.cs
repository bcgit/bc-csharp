using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

using Asn1Pkcs = Org.BouncyCastle.Asn1.Pkcs;

namespace Org.BouncyCastle.Cms
{
    /**
    * the KeyTransRecipientInformation class for a recipient who has been sent a secret
    * key encrypted using their public key that needs to be used to
    * extract the message.
    */
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
                    var subjectKeyIdentifier = (Asn1OctetString)r.ID;

                    rid.SubjectKeyIdentifier = subjectKeyIdentifier.GetEncoded(Asn1Encodable.Der);
                }
                else
                {
                    var issuerAndSerialNumber = (Asn1.Cms.IssuerAndSerialNumber)r.ID;

                    rid.Issuer = issuerAndSerialNumber.Issuer;
                    rid.SerialNumber = issuerAndSerialNumber.SerialNumber.Value;
                }
            }
            catch (IOException)
            {
                throw new ArgumentException("invalid rid in KeyTransRecipientInformation");
            }
        }

		private string GetExchangeEncryptionAlgorithmName(
			AlgorithmIdentifier algo)
		{
		    DerObjectIdentifier oid = algo.Algorithm;

            if (Asn1Pkcs.PkcsObjectIdentifiers.RsaEncryption.Equals(oid))
			{
				return "RSA//PKCS1Padding";
			} else if (Asn1Pkcs.PkcsObjectIdentifiers.IdRsaesOaep.Equals(oid))
            {
                 Asn1Pkcs.RsaesOaepParameters rsaParams = Asn1Pkcs.RsaesOaepParameters.GetInstance(algo.Parameters);                       
                return "RSA//OAEPWITH"+DigestUtilities.GetAlgorithmName(rsaParams.HashAlgorithm.Algorithm)+"ANDMGF1Padding";
            }

			return oid.Id;
		}

		internal KeyParameter UnwrapKey(ICipherParameters key)
		{
			byte[] encryptedKey = m_info.EncryptedKey.GetOctets();

			try
			{
				if (keyEncAlg.Algorithm.Equals(PkcsObjectIdentifiers.IdRsaesOaep))
				{
					IKeyUnwrapper keyWrapper = new Asn1KeyUnwrapper(keyEncAlg.Algorithm, keyEncAlg.Parameters, key);

					return ParameterUtilities.CreateKeyParameter(
							GetContentAlgorithmName(), keyWrapper.Unwrap(encryptedKey, 0, encryptedKey.Length).Collect());
				}
				else
				{
					string keyExchangeAlgorithm = GetExchangeEncryptionAlgorithmName(keyEncAlg);
					IWrapper keyWrapper = WrapperUtilities.GetWrapper(keyExchangeAlgorithm);
					keyWrapper.Init(false, key);

					// FIXME Support for MAC algorithm parameters similar to cipher parameters
					return ParameterUtilities.CreateKeyParameter(
						GetContentAlgorithmName(), keyWrapper.Unwrap(encryptedKey, 0, encryptedKey.Length));
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
//			catch (IllegalBlockSizeException e)
			catch (DataLengthException e)
			{
				throw new CmsException("illegal blocksize in message.", e);
			}
//			catch (BadPaddingException e)
			catch (InvalidCipherTextException e)
			{
				throw new CmsException("bad padding in message.", e);
			}
		}
		
		/**
        * decrypt the content and return it as a byte array.
        */
        public override CmsTypedStream GetContentStream(
            ICipherParameters key)
        {
			KeyParameter sKey = UnwrapKey(key);

			return GetContentFromSessionKey(sKey);
		}
    }
}
