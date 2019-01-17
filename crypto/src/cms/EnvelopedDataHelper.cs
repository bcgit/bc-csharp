using System.Collections;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Cms
{
    public class EnvelopedDataHelper
    {
        private static readonly IDictionary BaseCipherNames = Platform.CreateHashtable();
        private static readonly IDictionary MacAlgNames = Platform.CreateHashtable();

        private static readonly IDictionary prfs = Platform.CreateHashtable();


        public delegate IDigest DigestCreator();

        static EnvelopedDataHelper()
        {
            prfs.Add(PkcsObjectIdentifiers.IdHmacWithSha1, new DigestProvider(delegate () { return new Sha1Digest(); }));
            prfs.Add(PkcsObjectIdentifiers.IdHmacWithSha224, new DigestProvider(delegate () { return new Sha224Digest(); }));
            prfs.Add(PkcsObjectIdentifiers.IdHmacWithSha256, new DigestProvider(delegate () { return new Sha256Digest(); }));
            prfs.Add(PkcsObjectIdentifiers.IdHmacWithSha384, new DigestProvider(delegate () { return new Sha384Digest(); }));
            prfs.Add(PkcsObjectIdentifiers.IdHmacWithSha512, new DigestProvider(delegate () { return new Sha512Digest(); }));


            BaseCipherNames.Add(PkcsObjectIdentifiers.DesEde3Cbc, "DESEDE");
            BaseCipherNames.Add(NistObjectIdentifiers.IdAes128Cbc, "AES");
            BaseCipherNames.Add(NistObjectIdentifiers.IdAes192Cbc, "AES");
            BaseCipherNames.Add(NistObjectIdentifiers.IdAes256Cbc, "AES");

            MacAlgNames.Add(PkcsObjectIdentifiers.DesEde3Cbc, "DESEDEMac");
            MacAlgNames.Add(NistObjectIdentifiers.IdAes128Cbc, "AESMac");
            MacAlgNames.Add(NistObjectIdentifiers.IdAes192Cbc, "AESMac");
            MacAlgNames.Add(NistObjectIdentifiers.IdAes256Cbc, "AESMac");
            MacAlgNames.Add(PkcsObjectIdentifiers.RC2Cbc, "RC2Mac");
        }

        static IDigest GetPrf(AlgorithmIdentifier algID)
        {
            return ((DigestCreator)prfs[algID]).Invoke();
        }


        static IWrapper CreateRFC3211Wrapper(DerObjectIdentifier algorithm)

        {
            if (NistObjectIdentifiers.IdAes128Cbc.Equals(algorithm)
        || NistObjectIdentifiers.IdAes192Cbc.Equals(algorithm)
        || NistObjectIdentifiers.IdAes256Cbc.Equals(algorithm))
            {
                return new Rfc3211WrapEngine(new AesEngine());
            }
            else if (PkcsObjectIdentifiers.DesEde3Cbc.Equals(algorithm))
            {
                return new Rfc3211WrapEngine(new DesEdeEngine());
            }
            else if (OiwObjectIdentifiers.DesCbc.Equals(algorithm))
            {
                return new Rfc3211WrapEngine(new DesEngine());
            }
            else if (PkcsObjectIdentifiers.RC2Cbc.Equals(algorithm))
            {
                return new Rfc3211WrapEngine(new RC2Engine());
            }
            else
            {
                throw new CmsException("cannot recognise wrapper: " + algorithm);
            }
        }



       public static object CreateContentCipher(bool forEncryption, ICipherParameters encKey,
            AlgorithmIdentifier encryptionAlgID)

        {
            return CipherFactory.CreateContentCipher(forEncryption, encKey, encryptionAlgID);
        }


        public AlgorithmIdentifier GenerateEncryptionAlgID(DerObjectIdentifier encryptionOID, KeyParameter encKey, SecureRandom random)

        {
            return AlgorithmIdentifierFactory.GenerateEncryptionAlgID(encryptionOID, encKey.GetKey().Length * 8, random);
        }

       public  CipherKeyGenerator CreateKeyGenerator(DerObjectIdentifier algorithm, SecureRandom random)

        {
            return CipherKeyGeneratorFactory.CreateKeyGenerator(algorithm, random);
        }


    }

    // This exists because we can't directly put a delegate in a map as it is
    // not an object.
    internal class DigestProvider
    {
        private readonly EnvelopedDataHelper.DigestCreator creator;

        public DigestProvider(EnvelopedDataHelper.DigestCreator creator)
        {
            this.creator = creator;
        }

        public IDigest Create()
        {
            return creator.Invoke();
        }
    }
}