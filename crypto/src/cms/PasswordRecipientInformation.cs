using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cms
{
    /// <summary>The RecipientInfo class for a recipient who has been sent a message encrypted using a password.</summary>
    public class PasswordRecipientInformation
        : RecipientInformation
    {
        private readonly PasswordRecipientInfo m_info;

        internal PasswordRecipientInformation(PasswordRecipientInfo info, CmsSecureReadable secureReadable)
            : base(info.KeyEncryptionAlgorithm, secureReadable)
        {
            m_info = info ?? throw new ArgumentNullException(nameof(info));
            this.rid = new RecipientID();
        }

        /// <summary>
        /// Return the object identifier for the key derivation algorithm, or null if there is none present.
        /// </summary>
        public virtual AlgorithmIdentifier KeyDerivationAlgorithm => m_info.KeyDerivationAlgorithm;

        /// <summary>Decrypt the content and return an input stream.</summary>
        public override CmsTypedStream GetContentStream(ICipherParameters key)
        {
            try
            {
                AlgorithmIdentifier kekAlg = AlgorithmIdentifier.GetInstance(m_info.KeyEncryptionAlgorithm);
                Asn1Sequence kekAlgParams = (Asn1Sequence)kekAlg.Parameters;
                byte[] encryptedKey = m_info.EncryptedKey.GetOctets();
                string kekAlgName = DerObjectIdentifier.GetInstance(kekAlgParams[0]).Id;
                string cName = CmsEnvelopedHelper.GetRfc3211WrapperName(kekAlgName);
                IWrapper keyWrapper = WrapperUtilities.GetWrapper(cName);

                var iv = Asn1OctetString.GetInstance(kekAlgParams[1]);

                ICipherParameters parameters = ((CmsPbeKey)key).GetEncoded(kekAlgName);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                parameters = new ParametersWithIV(parameters, iv.GetOctetsSpan());
#else
                parameters = new ParametersWithIV(parameters, iv.GetOctets());
#endif

                keyWrapper.Init(false, parameters);

                KeyParameter sKey = ParameterUtilities.CreateKeyParameter(
                    GetContentAlgorithmName(), keyWrapper.Unwrap(encryptedKey, 0, encryptedKey.Length));

                return GetContentFromSessionKey(sKey);
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("couldn't create cipher.", e);
            }
            catch (InvalidKeyException e)
            {
                throw new CmsException("key invalid in message.", e);
            }
        }
    }
}
