using System.Collections;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Operators
{
    public class CmsContentEncryptorBuilder
    {
        private static readonly IDictionary keySizes = Platform.CreateHashtable();

        static CmsContentEncryptorBuilder()
        {
            keySizes[NistObjectIdentifiers.IdAes128Cbc] = 128;
            keySizes[NistObjectIdentifiers.IdAes192Cbc] =192;
            keySizes[NistObjectIdentifiers.IdAes256Cbc] =256;

           
            keySizes[NttObjectIdentifiers.IdCamellia128Cbc] =128;
            keySizes[NttObjectIdentifiers.IdCamellia192Cbc] =192;
            keySizes[NttObjectIdentifiers.IdCamellia256Cbc] =256;
        }

        private static int getKeySize(DerObjectIdentifier oid)
        {
            if (keySizes.Contains(oid))
            {
                return (int)keySizes[oid];
            }

            return -1;
        }

        private readonly DerObjectIdentifier encryptionOID;
        private readonly int keySize;

      
        private EnvelopedDataHelper helper = new EnvelopedDataHelper();
        private SecureRandom random;

        public CmsContentEncryptorBuilder(DerObjectIdentifier encryptionOID):this(encryptionOID, getKeySize(encryptionOID)) { 
        }

        public CmsContentEncryptorBuilder(DerObjectIdentifier encryptionOID, int keySize)
        {
            this.encryptionOID = encryptionOID;
            this.keySize = keySize;
        }

        public ICipherBuilderWithKey Build()
         {
            return new DefaultCipherBuilderWithKey(encryptionOID,keySize,random,new EnvelopedDataHelper());
        }

    }

    public class DefaultCipherBuilderWithKey:ICipherBuilderWithKey
    {

        private readonly KeyParameter encKey;
        private AlgorithmIdentifier algorithmIdentifier;
       
      


        public DefaultCipherBuilderWithKey(DerObjectIdentifier encryptionOID, int keySize, SecureRandom random,EnvelopedDataHelper helper)
        {
            if (random == null)
            {
                random= new SecureRandom();
            }

            CipherKeyGenerator keyGen = helper.CreateKeyGenerator(encryptionOID, random);
            encKey = new KeyParameter(keyGen.GenerateKey());
            algorithmIdentifier = helper.GenerateEncryptionAlgID(encryptionOID, encKey, random);
          //  cipher = EnvelopedDataHelper.CreateContentCipher(true, encKey, algorithmIdentifier);
        }


        public object AlgorithmDetails
        {
            get { return algorithmIdentifier; }
        }
        public int GetMaxOutputSize(int inputLen)
        {
            throw new System.NotImplementedException();
        }

        public ICipher BuildCipher(Stream stream)
        {

            object cipher = EnvelopedDataHelper.CreateContentCipher(true, encKey, algorithmIdentifier);

            //
            // BufferedBlockCipher
            // IStreamCipher
            //

            if (cipher is IStreamCipher)
            {
                   cipher = new BufferedStreamCipher((IStreamCipher)cipher);                
            }

            if (stream == null)
            {
                stream = new MemoryStream();
            }

            return new BufferedCipherWrapper((IBufferedCipher)cipher,stream);
        }

        public ICipherParameters Key
        {
            get { return encKey; }
        }
    }

    public class BufferedCipherWrapper : ICipher
    {
        private readonly IBufferedCipher bufferedCipher;
        private readonly CipherStream stream;

        public BufferedCipherWrapper(IBufferedCipher bufferedCipher, Stream source)
        {
            this.bufferedCipher = bufferedCipher;
            stream = new CipherStream(source, bufferedCipher, bufferedCipher);
        }

        public int GetMaxOutputSize(int inputLen)
        {
            return bufferedCipher.GetOutputSize(inputLen);
        }

        public int GetUpdateOutputSize(int inputLen)
        {
            return bufferedCipher.GetUpdateOutputSize(inputLen);
        }

        public Stream Stream
        {
            get { return stream; }
        }
    }
  

    

}