using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace Org.BouncyCastle.OpenSsl
{
    /// <summary>PEM generator for PKCS#8 private keys, optionally encrypted with a password-based algorithm.</summary>
    public class Pkcs8Generator
        : PemObjectGenerator
    {
        // TODO[Pkcs8Generator]
        //public static readonly DerObjectIdentifier Aes128Cbc = NistObjectIdentifiers.IdAes128Cbc;
        //public static readonly DerObjectIdentifier Aes192Cbc = NistObjectIdentifiers.IdAes192Cbc;
        //public static readonly DerObjectIdentifier Aes256Cbc = NistObjectIdentifiers.IdAes256Cbc;
        //public static readonly DerObjectIdentifier Des3Cbc = PkcsObjectIdentifiers.DesEde3Cbc;

        /// <summary>The PKCS#12 password-based encryption scheme using SHA-1 and 128 bit RC4.</summary>
        public static readonly DerObjectIdentifier PbeWithShaAnd128BitRC4 = PkcsObjectIdentifiers.PbeWithShaAnd128BitRC4;
        /// <summary>The PKCS#12 password-based encryption scheme using SHA-1 and 40 bit RC4.</summary>
        public static readonly DerObjectIdentifier PbeWithShaAnd40BitRC4 = PkcsObjectIdentifiers.PbeWithShaAnd40BitRC4;
        /// <summary>
        /// The PKCS#12 password-based encryption scheme using SHA-1 and three-key triple DES in CBC mode.
        /// </summary>
        public static readonly DerObjectIdentifier PbeWithShaAnd3KeyTripleDesCbc = PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc;
        /// <summary>
        /// The PKCS#12 password-based encryption scheme using SHA-1 and two-key triple DES in CBC mode.
        /// </summary>
        public static readonly DerObjectIdentifier PbeWithShaAnd2KeyTripleDesCbc = PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc;
        /// <summary>The PKCS#12 password-based encryption scheme using SHA-1 and 128 bit RC2 in CBC mode.</summary>
        public static readonly DerObjectIdentifier PbeWithShaAnd128BitRC2Cbc = PkcsObjectIdentifiers.PbeWithShaAnd128BitRC2Cbc;
        /// <summary>The PKCS#12 password-based encryption scheme using SHA-1 and 40 bit RC2 in CBC mode.</summary>
        public static readonly DerObjectIdentifier PbewithShaAnd40BitRC2Cbc = PkcsObjectIdentifiers.PbewithShaAnd40BitRC2Cbc;

        // TODO[Pkcs8Generator]
        //public static readonly AlgorithmIdentifier PrfHmacSha1 = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha1, DerNull.Instance);
        //public static readonly AlgorithmIdentifier PrfHmacSha224 = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha224, DerNull.Instance);
        //public static readonly AlgorithmIdentifier PrfHmacSha256 = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha256, DerNull.Instance);
        //public static readonly AlgorithmIdentifier PrfHmacSha384 = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha384, DerNull.Instance);
        //public static readonly AlgorithmIdentifier PrfHmacSha512 = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha512, DerNull.Instance);
        //public static readonly AlgorithmIdentifier PrfHmacSha3_224 = new AlgorithmIdentifier(NistObjectIdentifiers.IdHMacWithSha3_224, DerNull.Instance);
        //public static readonly AlgorithmIdentifier PrfHmacSha3_256 = new AlgorithmIdentifier(NistObjectIdentifiers.IdHMacWithSha3_256, DerNull.Instance);
        //public static readonly AlgorithmIdentifier PrfHmacSha3_384 = new AlgorithmIdentifier(NistObjectIdentifiers.IdHMacWithSha3_384, DerNull.Instance);
        //public static readonly AlgorithmIdentifier PrfHmacSha3_512 = new AlgorithmIdentifier(NistObjectIdentifiers.IdHMacWithSha3_512, DerNull.Instance);
        //public static readonly AlgorithmIdentifier PrfHmacGost3411 = new AlgorithmIdentifier(CryptoProObjectIdentifiers.GostR3411Hmac, DerNull.Instance);

        /// <summary>The PKCS#12 PBE algorithm with SHA-1 and 128 bit RC4.</summary>
        [Obsolete("Use 'PbeWithShaAnd128BitRC4' instead")]
        public static readonly string PbeSha1_RC4_128 = PkcsObjectIdentifiers.PbeWithShaAnd128BitRC4.Id;
        /// <summary>The PKCS#12 PBE algorithm with SHA-1 and 40 bit RC4.</summary>
        [Obsolete("Use 'PbeWithShaAnd40BitRC4' instead")]
        public static readonly string PbeSha1_RC4_40 = PkcsObjectIdentifiers.PbeWithShaAnd40BitRC4.Id;
        /// <summary>The PKCS#12 PBE algorithm with SHA-1 and three-key Triple DES.</summary>
        [Obsolete("Use 'PbeWithShaAnd3KeyTripleDesCbc' instead")]
        public static readonly string PbeSha1_3DES = PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc.Id;
        /// <summary>The PKCS#12 PBE algorithm with SHA-1 and two-key Triple DES.</summary>
        [Obsolete("Use 'PbeWithShaAnd2KeyTripleDesCbc' instead")]
        public static readonly string PbeSha1_2DES = PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc.Id;
        /// <summary>The PKCS#12 PBE algorithm with SHA-1 and 128 bit RC2.</summary>
        [Obsolete("Use 'PbeWithShaAnd128BitRC2Cbc' instead")]
        public static readonly string PbeSha1_RC2_128 = PkcsObjectIdentifiers.PbeWithShaAnd128BitRC2Cbc.Id;
        /// <summary>The PKCS#12 PBE algorithm with SHA-1 and 40 bit RC2.</summary>
        [Obsolete("Use 'PbewithShaAnd40BitRC2Cbc' instead")]
        public static readonly string PbeSha1_RC2_40 = PkcsObjectIdentifiers.PbewithShaAnd40BitRC2Cbc.Id;

        private char[] password;
        private string algorithm;
        private int iterationCount;
        private AsymmetricKeyParameter privKey;
        private SecureRandom random;

        /// <summary>Constructor for an unencrypted private key PEM object.</summary>
        /// <param name="privKey">The private key to be encoded.</param>
        public Pkcs8Generator(AsymmetricKeyParameter privKey)
        {
            this.privKey = privKey;
        }

        /// <summary>Constructor for an encrypted private key PEM object.</summary>
        /// <param name="privKey">The private key to be encoded.</param>
        /// <param name="algorithm">The object identifier (as a string) of the password-based encryption algorithm.
        /// </param>
        public Pkcs8Generator(AsymmetricKeyParameter privKey, string algorithm)
            : this(privKey, new DerObjectIdentifier(algorithm))
        {
            this.privKey = privKey;
            this.algorithm = algorithm;
            this.iterationCount = 2048;
        }

        /// <summary>Constructor for an encrypted private key PEM object.</summary>
        /// <param name="privKey">The private key to be encoded.</param>
        /// <param name="algorithm">The object identifier of the password-based encryption algorithm.</param>
        /// <exception cref="ArgumentNullException"><paramref name="privKey"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="privKey"/> is not a private key.</exception>
        public Pkcs8Generator(AsymmetricKeyParameter privKey, DerObjectIdentifier algorithm)
        {
            if (privKey == null)
                throw new ArgumentNullException(nameof(privKey));
            if (!privKey.IsPrivate)
                throw new ArgumentException("Expected private key", nameof(privKey));

            this.privKey = privKey;
            this.algorithm = algorithm.Id;
            this.iterationCount = 2048;
        }

        /// <summary>Sets the source of randomness used to generate the salt; the default is used if not set.</summary>
        public SecureRandom SecureRandom
        {
            set { this.random = value; }
        }

        /// <summary>Sets the password to encrypt the key with.</summary>
        public char[] Password
        {
            set { this.password = value; }
        }

        /// <summary>Sets the iteration count for the key derivation (default 2048).</summary>
        public int IterationCount
        {
            set { this.iterationCount = value; }
        }

        /// <summary>Generate the PEM object.</summary>
        /// <returns>
        /// The <see cref="PemObject"/>: "PRIVATE KEY" if unencrypted, otherwise "ENCRYPTED PRIVATE KEY".
        /// </returns>
        /// <exception cref="PemGenerationException">The key could not be encrypted.</exception>
        public PemObject Generate()
        {
            if (algorithm == null)
            {
                PrivateKeyInfo pki = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privKey);

                return new PemObject("PRIVATE KEY", pki.GetEncoded());
            }

            random = CryptoServicesRegistrar.GetSecureRandom(random);

            // TODO[Pkcs8Generator] The amount of salt needed depends on the algorithm?
            byte[] salt = SecureRandom.GetNextBytes(random, 20);

            try
            {
                EncryptedPrivateKeyInfo epki = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
                    algorithm, password, salt, iterationCount, privKey);

                return new PemObject("ENCRYPTED PRIVATE KEY", epki.GetEncoded());
            }
            catch (Exception e)
            {
                throw new PemGenerationException("Couldn't encrypt private key", e);
            }
        }
    }
}
