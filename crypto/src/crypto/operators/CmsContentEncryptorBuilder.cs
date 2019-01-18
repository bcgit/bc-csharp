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
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;

namespace Org.BouncyCastle.Operators
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
            return new Asn1CipherBuilderWithKey(encryptionOID,keySize,random);
        }
    }
}
