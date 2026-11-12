using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>Builder for PKCS#8 EncryptedPrivateKeyInfo objects.</summary>
    public class Pkcs8EncryptedPrivateKeyInfoBuilder
    {
        private readonly PrivateKeyInfo m_privateKeyInfo;

        /// <summary>Create a builder for the private key given as an encoded PrivateKeyInfo.</summary>
        /// <param name="privateKeyInfo">The encoded PrivateKeyInfo.</param>
        public Pkcs8EncryptedPrivateKeyInfoBuilder(byte[] privateKeyInfo)
            : this(PrivateKeyInfo.GetInstance(privateKeyInfo))
        {
        }

        /// <summary>Create a builder for the given private key.</summary>
        /// <param name="privateKeyInfo">The private key to encrypt.</param>
        /// <exception cref="ArgumentNullException"><paramref name="privateKeyInfo"/> is null.</exception>
        public Pkcs8EncryptedPrivateKeyInfoBuilder(PrivateKeyInfo privateKeyInfo)
        {
            m_privateKeyInfo = privateKeyInfo ?? throw new ArgumentNullException(nameof(privateKeyInfo));
        }

        /// <summary>
        /// Create the encrypted private key info using the passed in encryptor.
        /// </summary>
        /// <param name="encryptor">The encryptor to use.</param>
        /// <returns>An encrypted private key info containing the original private key info.</returns>
        /// <exception cref="InvalidOperationException">The private key info could not be encoded.</exception>
        public Pkcs8EncryptedPrivateKeyInfo Build(ICipherBuilder encryptor)
        {
            try
            {
                var encryptionAlgorithm = (AlgorithmIdentifier)encryptor.AlgorithmDetails;

                MemoryStream bOut = new MemoryStream();
                ICipher cOut = encryptor.BuildCipher(bOut);

                using (var stream = cOut.Stream)
                {
                    m_privateKeyInfo.EncodeTo(stream);
                }

                var encryptedData = DerOctetString.WithContents(bOut.ToArray());
                return new Pkcs8EncryptedPrivateKeyInfo(
                    new EncryptedPrivateKeyInfo(encryptionAlgorithm, encryptedData));
            }
            catch (IOException)
            {
                throw new InvalidOperationException("cannot encode privateKeyInfo");
            }
        }
    }
}
