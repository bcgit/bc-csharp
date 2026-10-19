using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Operators
{
    /// <summary>
    /// A cipher builder for a content encryption algorithm, holding the key and the algorithm identifier.
    /// </summary>
    public class Asn1CipherBuilderWithKey
        : ICipherBuilderWithKey
    {
        private readonly KeyParameter m_cipherKey;
        private readonly AlgorithmIdentifier m_cipherAlgID;
        private readonly ICipherParameters m_cipherParameters;

        /// <summary>Create a new <see cref="Asn1CipherBuilderWithKey"/>.</summary>
        /// <param name="encryptionOID">The encryption OID.</param>
        /// <param name="keySize">The key size in bits.</param>
        /// <param name="random">The source of randomness.</param>
        public Asn1CipherBuilderWithKey(DerObjectIdentifier encryptionOID, int keySize, SecureRandom random)
        {
            random = CryptoServicesRegistrar.GetSecureRandom(random);

            CipherKeyGenerator cipherKeyGen = GeneratorUtilities.GetKeyGenerator(encryptionOID);
            if (keySize < 0)
            {
                keySize = cipherKeyGen.DefaultStrength;
            }
            cipherKeyGen.Init(new KeyGenerationParameters(random, keySize));
            byte[] cipherKeyBytes = cipherKeyGen.GenerateKey();
            m_cipherKey = ParameterUtilities.CreateKeyParameter(encryptionOID, cipherKeyBytes);

            Asn1Encodable asn1Params = ImplGenerateAsn1Parameters(random, encryptionOID.GetID(), cipherKeyBytes);
            m_cipherAlgID = ImplGetAlgorithmIdentifier(encryptionOID.GetID(), m_cipherKey, asn1Params,
                out var cipherParameters);
            m_cipherParameters = new ParametersWithRandom(cipherParameters, random);
        }

        /// <inheritdoc/>
        public object AlgorithmDetails => m_cipherAlgID;

        /// <inheritdoc/>
        public int GetMaxOutputSize(int inputLen) => throw new NotImplementedException();

        /// <inheritdoc/>
        public ICipher BuildCipher(Stream stream)
        {
            IBufferedCipher writeCipher = CipherUtilities.GetCipher(m_cipherAlgID.Algorithm);
            writeCipher.Init(forEncryption: true, m_cipherParameters);
            return new BufferedCipherWrapper(writeCipher, stream);
        }

        /// <inheritdoc/>
        public ICipherParameters Key => m_cipherKey;

        internal static Asn1Encodable ImplGenerateAsn1Parameters(SecureRandom random, string encryptionOid,
            byte[] encKeyBytes)
        {
            try
            {
                if (PkcsObjectIdentifiers.RC2Cbc.GetID().Equals(encryptionOid))
                {
                    byte[] iv = new byte[8];
                    random.NextBytes(iv);

                    int effectiveKeyBits = encKeyBytes.Length * 8;
                    int parameterVersion = RC2CbcUtilities.GetParameterVersion(effectiveKeyBits);

                    return new RC2CbcParameter(parameterVersion, iv);
                }

                return ParameterUtilities.GenerateParameters(encryptionOid, random);
            }
            catch (SecurityUtilityException)
            {
                // TODO Add a TryGenerateParameters or similar method on ParameterUtilities to avoid exceptions
                return null;
            }
        }

        internal static AlgorithmIdentifier ImplGetAlgorithmIdentifier(string encryptionOid,
            KeyParameter encKey, Asn1Encodable asn1Params, out ICipherParameters cipherParameters)
        {
            Asn1Object asn1Object;
            if (asn1Params != null)
            {
                asn1Object = asn1Params.ToAsn1Object();
                // TODO[cms] We'd prefer not to have to force Asn1Object conversion to call this
                cipherParameters = ParameterUtilities.GetCipherParameters(encryptionOid, encKey, asn1Object);
            }
            else
            {
                // TODO[cms] Should this be NoParams depending on the encryption algorithm?
                asn1Object = DerNull.Instance;
                cipherParameters = encKey;
            }

            return new AlgorithmIdentifier(new DerObjectIdentifier(encryptionOid), asn1Object);
        }
    }

    /// <summary>Wraps a buffered cipher as an <see cref="ICipher"/>.</summary>
    public class BufferedCipherWrapper
        : ICipher
    {
        private readonly IBufferedCipher m_bufferedCipher;
        private readonly CipherStream m_stream;

        /// <summary>Create a new <see cref="BufferedCipherWrapper"/>.</summary>
        /// <param name="bufferedCipher">The buffered cipher.</param>
        /// <param name="source">The source.</param>
        public BufferedCipherWrapper(IBufferedCipher bufferedCipher, Stream source)
        {
            m_bufferedCipher = bufferedCipher;
            m_stream = new CipherStream(source, bufferedCipher, bufferedCipher);
        }

        /// <inheritdoc/>
        public int GetMaxOutputSize(int inputLen) => m_bufferedCipher.GetOutputSize(inputLen);

        /// <inheritdoc/>
        public int GetUpdateOutputSize(int inputLen) => m_bufferedCipher.GetUpdateOutputSize(inputLen);

        public Stream Stream => m_stream;
    }
}
