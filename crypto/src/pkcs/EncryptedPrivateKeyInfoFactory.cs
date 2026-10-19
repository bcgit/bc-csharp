using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>Factory for the PKCS#8 EncryptedPrivateKeyInfo structure, protecting a private key with a password.
    /// </summary>
    public sealed class EncryptedPrivateKeyInfoFactory
    {
        private EncryptedPrivateKeyInfoFactory()
        {
        }

        /// <summary>Encrypt a private key using a password-based encryption (PBE) algorithm.</summary>
        /// <param name="algorithm">The object identifier of the PBE algorithm.</param>
        /// <param name="passPhrase">The password to derive the encryption key from.</param>
        /// <param name="salt">The salt for the key derivation.</param>
        /// <param name="iterationCount">The iteration count for the key derivation.</param>
        /// <param name="key">The private key to encrypt.</param>
        /// <returns>The EncryptedPrivateKeyInfo.</returns>
        /// <exception cref="Exception">The encryption algorithm is unknown.</exception>
        public static EncryptedPrivateKeyInfo CreateEncryptedPrivateKeyInfo(
            DerObjectIdentifier algorithm,
            char[] passPhrase,
            byte[] salt,
            int iterationCount,
            AsymmetricKeyParameter key)
        {
            return CreateEncryptedPrivateKeyInfo(
                algorithm.Id, passPhrase, salt, iterationCount,
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(key));
        }

        /// <summary>Encrypt a private key using a password-based encryption (PBE) algorithm.</summary>
        /// <param name="algorithm">The name or object identifier (as a string) of the PBE algorithm.</param>
        /// <param name="passPhrase">The password to derive the encryption key from.</param>
        /// <param name="salt">The salt for the key derivation.</param>
        /// <param name="iterationCount">The iteration count for the key derivation.</param>
        /// <param name="key">The private key to encrypt.</param>
        /// <returns>The EncryptedPrivateKeyInfo.</returns>
        /// <exception cref="Exception">The encryption algorithm is unknown.</exception>
        public static EncryptedPrivateKeyInfo CreateEncryptedPrivateKeyInfo(
            string algorithm,
            char[] passPhrase,
            byte[] salt,
            int iterationCount,
            AsymmetricKeyParameter key)
        {
            return CreateEncryptedPrivateKeyInfo(
                algorithm, passPhrase, salt, iterationCount,
                PrivateKeyInfoFactory.CreatePrivateKeyInfo(key));
        }

        /// <summary>Encrypt a PrivateKeyInfo using a password-based encryption (PBE) algorithm.</summary>
        /// <param name="algorithm">The name or object identifier (as a string) of the PBE algorithm.</param>
        /// <param name="passPhrase">The password to derive the encryption key from.</param>
        /// <param name="salt">The salt for the key derivation.</param>
        /// <param name="iterationCount">The iteration count for the key derivation.</param>
        /// <param name="keyInfo">The private key info to encrypt.</param>
        /// <returns>The EncryptedPrivateKeyInfo.</returns>
        /// <exception cref="Exception">The encryption algorithm is unknown.</exception>
        public static EncryptedPrivateKeyInfo CreateEncryptedPrivateKeyInfo(
            string algorithm,
            char[] passPhrase,
            byte[] salt,
            int iterationCount,
            PrivateKeyInfo keyInfo)
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

        /// <summary>Encrypt a private key using PBES2 with the given cipher and pseudo-random function.</summary>
        /// <param name="cipherAlgorithm">The object identifier of the cipher.</param>
        /// <param name="prfAlgorithm">The object identifier of the PBKDF2 pseudo-random function.</param>
        /// <param name="passPhrase">The password to derive the encryption key from.</param>
        /// <param name="salt">The salt for the key derivation.</param>
        /// <param name="iterationCount">The iteration count for the key derivation.</param>
        /// <param name="random">The source of randomness for the algorithm parameters.</param>
        /// <param name="key">The private key to encrypt.</param>
        /// <returns>The EncryptedPrivateKeyInfo.</returns>
        /// <exception cref="Exception">The cipher algorithm is unknown.</exception>
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

        /// <summary>Encrypt a PrivateKeyInfo using PBES2 with the given cipher and pseudo-random function.</summary>
        /// <param name="cipherAlgorithm">The object identifier of the cipher.</param>
        /// <param name="prfAlgorithm">The object identifier of the PBKDF2 pseudo-random function.</param>
        /// <param name="passPhrase">The password to derive the encryption key from.</param>
        /// <param name="salt">The salt for the key derivation.</param>
        /// <param name="iterationCount">The iteration count for the key derivation.</param>
        /// <param name="random">The source of randomness for the algorithm parameters.</param>
        /// <param name="keyInfo">The private key info to encrypt.</param>
        /// <returns>The EncryptedPrivateKeyInfo.</returns>
        /// <exception cref="Exception">The cipher algorithm is unknown.</exception>
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
