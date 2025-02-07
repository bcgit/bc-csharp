using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pkcs
{
    public sealed class EncryptedPrivateKeyInfoFactory
    {
        private EncryptedPrivateKeyInfoFactory()
        {
        }

        public static EncryptedPrivateKeyInfo CreateEncryptedPrivateKeyInfo(
            DerObjectIdentifier		algorithm,
            char[]					passPhrase,
            byte[]					salt,
            int						iterationCount,
            AsymmetricKeyParameter	key)
        {
            return CreateEncryptedPrivateKeyInfo(
                algorithm.Id, passPhrase, salt, iterationCount,
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(key));
        }

        public static EncryptedPrivateKeyInfo CreateEncryptedPrivateKeyInfo(
            string					algorithm,
            char[]					passPhrase,
            byte[]					salt,
            int						iterationCount,
            AsymmetricKeyParameter	key)
        {
            return CreateEncryptedPrivateKeyInfo(
                algorithm, passPhrase, salt, iterationCount,
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(key));
        }

        public static EncryptedPrivateKeyInfo CreateEncryptedPrivateKeyInfo(
            string			algorithm,
            char[]			passPhrase,
            byte[]			salt,
            int				iterationCount,
            PrivateKeyInfo	keyInfo)
        {
            if (!(PbeUtilities.CreateEngine(algorithm) is IBufferedCipher cipher))
                throw new Exception("Unknown encryption algorithm: " + algorithm);

            Asn1Encodable pbeParameters = PbeUtilities.GenerateAlgorithmParameters(
                algorithm, salt, iterationCount);
            ICipherParameters cipherParameters = PbeUtilities.GenerateCipherParameters(
                algorithm, passPhrase, pbeParameters);
            cipher.Init(true, cipherParameters);
            byte[] encoding = cipher.DoFinal(keyInfo.GetEncoded());

            var oid = PbeUtilities.GetObjectIdentifier(algorithm);
            var encryptionAlgorithm = new AlgorithmIdentifier(oid, pbeParameters);
            var encryptedData = DerOctetString.WithContents(encoding);
            return new EncryptedPrivateKeyInfo(encryptionAlgorithm, encryptedData);
        }

        public static EncryptedPrivateKeyInfo CreateEncryptedPrivateKeyInfo(
            DerObjectIdentifier cipherAlgorithm,
            DerObjectIdentifier prfAlgorithm,
            char[] passPhrase,
            byte[] salt,
            int iterationCount,
            SecureRandom random,
            AsymmetricKeyParameter key)
        {
            return CreateEncryptedPrivateKeyInfo(
                cipherAlgorithm, prfAlgorithm, passPhrase, salt, iterationCount, random,
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(key));
        }

        public static EncryptedPrivateKeyInfo CreateEncryptedPrivateKeyInfo(
            DerObjectIdentifier cipherAlgorithm,
            DerObjectIdentifier prfAlgorithm,
            char[] passPhrase,
            byte[] salt,
            int iterationCount,
            SecureRandom random,
            PrivateKeyInfo keyInfo)
        {
            if (!(CipherUtilities.GetCipher(cipherAlgorithm) is IBufferedCipher cipher))
                throw new Exception("Unknown encryption algorithm: " + cipherAlgorithm);

            Asn1Encodable pbeParameters = PbeUtilities.GenerateAlgorithmParameters(
                cipherAlgorithm, prfAlgorithm, salt, iterationCount, random);
            ICipherParameters cipherParameters = PbeUtilities.GenerateCipherParameters(
                PkcsObjectIdentifiers.IdPbeS2, passPhrase, pbeParameters);
            cipher.Init(true, cipherParameters);
            byte[] encoding = cipher.DoFinal(keyInfo.GetEncoded());

            var encryptionAlgorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbeS2, pbeParameters);
            var encryptedData = DerOctetString.WithContents(encoding);
            return new EncryptedPrivateKeyInfo(encryptionAlgorithm, encryptedData);
        }
    }
}
