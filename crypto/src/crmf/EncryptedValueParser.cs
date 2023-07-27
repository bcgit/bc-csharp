using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crmf
{
    /// <summary>Parser for EncryptedValue structures.</summary>
    public class EncryptedValueParser
    {
        private readonly EncryptedValue m_value;
        private readonly IEncryptedValuePadder m_padder;

        /**
         * Basic constructor - create a parser to read the passed in value.
         *
         * @param value the value to be parsed.
         */
        public EncryptedValueParser(EncryptedValue value)
            : this(value, null)
        {
        }

        /**
         * Create a parser to read the passed in value, assuming the padder was
         * applied to the data prior to encryption.
         *
         * @param value  the value to be parsed.
         * @param padder the padder to be used to remove padding from the decrypted value..
         */
        public EncryptedValueParser(EncryptedValue value, IEncryptedValuePadder padder)
        {
            m_value = value;
            m_padder = padder;
        }

        public virtual AlgorithmIdentifier IntendedAlg => m_value.IntendedAlg;

        // TODO[crmf]
#if false
        private virtual byte[] DecryptValue(ValueDecryptorGenerator decGen)
        {
            if (m_value.ValueHint != null)
                throw new NotSupportedException();

            InputDecryptor decryptor = decGen.getValueDecryptor(value.getKeyAlg(),
                value.getSymmAlg(), value.getEncSymmKey().getBytes());
            InputStream dataIn = decryptor.getInputStream(new ByteArrayInputStream(
                value.getEncValue().getBytes()));
            try
            {
                return UnpadData(Streams.readAll(dataIn));
            }
            catch (IOException e)
            {
                throw new CRMFException("Cannot parse decrypted data: " + e.getMessage(), e);
            }
        }

        /**
         * Read a X.509 certificate.
         *
         * @param decGen the decryptor generator to decrypt the encrypted value.
         * @return an X509CertificateHolder containing the certificate read.
         * @throws CRMFException if the decrypted data cannot be parsed, or a decryptor cannot be generated.
         */
        public virtual X509Certificate ReadCertificate(ValueDecryptorGenerator decGen)
        {
            return new X509Certificate(X509CertificateStructure.GetInstance(DecryptValue(decGen)));
        }

        /**
         * Read a PKCS#8 PrivateKeyInfo.
         *
         * @param decGen the decryptor generator to decrypt the encrypted value.
         * @return an PrivateKeyInfo containing the private key that was read.
         * @throws CRMFException if the decrypted data cannot be parsed, or a decryptor cannot be generated.
         */
        public virtual PrivateKeyInfo ReadPrivateKeyInfo(ValueDecryptorGenerator decGen)
        {
            return PrivateKeyInfo.GetInstance(DecryptValue(decGen));
        }

        /**
         * Read a pass phrase.
         *
         * @param decGen the decryptor generator to decrypt the encrypted value.
         * @return a pass phrase as recovered from the encrypted value.
         * @throws CRMFException if the decrypted data cannot be parsed, or a decryptor cannot be generated.
         */
        public virtual char[] ReadPassphrase(ValueDecryptorGenerator decGen)
        {
            return Strings.FromUtf8ByteArray(DecryptValue(decGen)).ToCharArray();
        }
#endif

        private byte[] UnpadData(byte[] data) => m_padder?.GetUnpaddedData(data) ?? data;
    }
}
