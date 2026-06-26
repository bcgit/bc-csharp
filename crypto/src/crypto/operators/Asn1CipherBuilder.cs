using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Operators
{
    public class Asn1CipherBuilderWithKey
        : ICipherBuilderWithKey
    {
        private readonly KeyParameter m_encKey;
        private AlgorithmIdentifier m_algID;

        public Asn1CipherBuilderWithKey(DerObjectIdentifier encryptionOID, int keySize, SecureRandom random)
        {
            random = CryptoServicesRegistrar.GetSecureRandom(random);

            CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOID);
            if (keySize < 0)
            {
                keySize = keyGen.DefaultStrength;
            }
            keyGen.Init(new KeyGenerationParameters(random, keySize));

            m_encKey = keyGen.GenerateKeyParameter();
            m_algID = AlgorithmIdentifierFactory.GenerateEncryptionAlgID(encryptionOID, m_encKey.KeyLength * 8, random);
        }

        public object AlgorithmDetails => m_algID;

        public int GetMaxOutputSize(int inputLen) => throw new NotImplementedException();

        public ICipher BuildCipher(Stream stream)
        {
            object cipher = CipherFactory.CreateContentCipher(true, m_encKey, m_algID);

            //
            // BufferedBlockCipher
            // IStreamCipher
            //

            if (cipher is IStreamCipher streamCipher)
            {
                cipher = new BufferedStreamCipher(streamCipher);
            }

            if (stream == null)
            {
                stream = new MemoryStream();
            }

            return new BufferedCipherWrapper((IBufferedCipher)cipher, stream);
        }

        public ICipherParameters Key => m_encKey;
    }

    public class BufferedCipherWrapper
        : ICipher
    {
        private readonly IBufferedCipher m_bufferedCipher;
        private readonly CipherStream m_stream;

        public BufferedCipherWrapper(IBufferedCipher bufferedCipher, Stream source)
        {
            m_bufferedCipher = bufferedCipher;
            m_stream = new CipherStream(source, bufferedCipher, bufferedCipher);
        }

        public int GetMaxOutputSize(int inputLen) => m_bufferedCipher.GetOutputSize(inputLen);

        public int GetUpdateOutputSize(int inputLen) => m_bufferedCipher.GetUpdateOutputSize(inputLen);

        public Stream Stream => m_stream;
    }
}
