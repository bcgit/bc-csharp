using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    /// <summary>
    /// Base class for CMS recipient information. Use <see cref="RecipientID"/> to select a recipient, then supply
    /// the matching key material to <see cref="GetContentStream(ICipherParameters)"/> or <see cref="GetContent"/>.
    /// </summary>
    public abstract class RecipientInformation
    {
        internal RecipientID rid = new RecipientID();
        internal AlgorithmIdentifier keyEncAlg;
        internal CmsSecureReadable secureReadable;

        private byte[] resultMac;

        internal RecipientInformation(AlgorithmIdentifier keyEncAlg, CmsSecureReadable secureReadable)
        {
            this.keyEncAlg = keyEncAlg;
            this.secureReadable = secureReadable;
        }

        internal string GetContentAlgorithmName()
        {
            AlgorithmIdentifier algorithm = secureReadable.Algorithm;
            //return CmsEnvelopedHelper.Instance.GetSymmetricCipherName(algorithm.Algorithm.Id);
            return algorithm.Algorithm.Id;
        }

        /// <summary>Gets the identifier used to match this recipient.</summary>
        public RecipientID RecipientID => rid;

        /// <summary>Gets the algorithm identifier used to encrypt or wrap the content-encryption key.</summary>
        public AlgorithmIdentifier KeyEncryptionAlgorithmID => keyEncAlg;

        /// <summary>Return the object identifier for the key encryption algorithm.</summary>
        public string KeyEncryptionAlgOid => keyEncAlg.Algorithm.GetID();

        /// <summary>
        /// Return the ASN.1 encoded key encryption algorithm parameters, or null if there aren't any.
        /// </summary>
        public Asn1Object KeyEncryptionAlgParams => keyEncAlg.Parameters?.ToAsn1Object();

        internal CmsTypedStream GetContentFromSessionKey(KeyParameter sKey)
        {
            CmsReadable readable = secureReadable.GetReadable(sKey);

            try
            {
                return new CmsTypedStream(readable.GetInputStream());
            }
            catch (IOException e)
            {
                throw new CmsException("error getting .", e);
            }
        }

        /// <summary>Decrypts the content using <paramref name="key"/> and returns all of its bytes.</summary>
        /// <param name="key">The recipient key material needed to recover the content-encryption key.</param>
        /// <returns>The decrypted or authenticated content.</returns>
        public byte[] GetContent(ICipherParameters key)
        {
            try
            {
                return CmsUtilities.StreamToByteArray(GetContentStream(key).ContentStream);
            }
            catch (IOException e)
            {
                throw new Exception("unable to parse internal stream: " + e);
            }
        }

        /// <summary>
        /// Return the MAC calculated for the content stream. Note: this call is only meaningful once all the content
        /// has been read.
        /// </summary>
        public byte[] GetMac()
        {
            if (resultMac == null)
            {
                object cryptoObject = secureReadable.CryptoObject;
                if (cryptoObject is IMac mac)
                {
                    resultMac = MacUtilities.DoFinal(mac);
                }
            }

            return Arrays.Clone(resultMac);
        }

        /// <summary>Returns a stream that exposes the recovered content.</summary>
        /// <param name="key">The recipient key material needed to recover the content-encryption key.</param>
        /// <returns>A typed stream over the recovered content.</returns>
        public abstract CmsTypedStream GetContentStream(ICipherParameters key);
    }
}
