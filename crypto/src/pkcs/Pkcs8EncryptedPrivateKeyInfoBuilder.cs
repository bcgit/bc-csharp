using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pkcs
{
    public class Pkcs8EncryptedPrivateKeyInfoBuilder
    {
        private readonly PrivateKeyInfo m_privateKeyInfo;

        public Pkcs8EncryptedPrivateKeyInfoBuilder(byte[] privateKeyInfo)
            : this(PrivateKeyInfo.GetInstance(privateKeyInfo))
        {
        }

        public Pkcs8EncryptedPrivateKeyInfoBuilder(PrivateKeyInfo privateKeyInfo)
        {
            m_privateKeyInfo = privateKeyInfo ?? throw new ArgumentNullException(nameof(privateKeyInfo));
        }

        /// <summary>
        /// Create the encrypted private key info using the passed in encryptor.
        /// </summary>
        /// <param name="encryptor">The encryptor to use.</param>
        /// <returns>An encrypted private key info containing the original private key info.</returns>
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
