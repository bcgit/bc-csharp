using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace Org.BouncyCastle.OpenSsl
{
    public class Pkcs8Generator
        : PemObjectGenerator
    {
        // TODO[Pkcs8Generator]
        //public static readonly DerObjectIdentifier Aes128Cbc = NistObjectIdentifiers.IdAes128Cbc;
        //public static readonly DerObjectIdentifier Aes192Cbc = NistObjectIdentifiers.IdAes192Cbc;
        //public static readonly DerObjectIdentifier Aes256Cbc = NistObjectIdentifiers.IdAes256Cbc;
        //public static readonly DerObjectIdentifier Des3Cbc = PkcsObjectIdentifiers.DesEde3Cbc;

        public static readonly DerObjectIdentifier PbeWithShaAnd128BitRC4 = PkcsObjectIdentifiers.PbeWithShaAnd128BitRC4;
        public static readonly DerObjectIdentifier PbeWithShaAnd40BitRC4 = PkcsObjectIdentifiers.PbeWithShaAnd40BitRC4;
        public static readonly DerObjectIdentifier PbeWithShaAnd3KeyTripleDesCbc = PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc;
        public static readonly DerObjectIdentifier PbeWithShaAnd2KeyTripleDesCbc = PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc;
        public static readonly DerObjectIdentifier PbeWithShaAnd128BitRC2Cbc = PkcsObjectIdentifiers.PbeWithShaAnd128BitRC2Cbc;
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

        [Obsolete("Use 'PbeWithShaAnd128BitRC4' instead")]
        public static readonly string PbeSha1_RC4_128 = PkcsObjectIdentifiers.PbeWithShaAnd128BitRC4.Id;
        [Obsolete("Use 'PbeWithShaAnd40BitRC4' instead")]
        public static readonly string PbeSha1_RC4_40 = PkcsObjectIdentifiers.PbeWithShaAnd40BitRC4.Id;
        [Obsolete("Use 'PbeWithShaAnd3KeyTripleDesCbc' instead")]
        public static readonly string PbeSha1_3DES = PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc.Id;
        [Obsolete("Use 'PbeWithShaAnd2KeyTripleDesCbc' instead")]
        public static readonly string PbeSha1_2DES = PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc.Id;
        [Obsolete("Use 'PbeWithShaAnd128BitRC2Cbc' instead")]
        public static readonly string PbeSha1_RC2_128 = PkcsObjectIdentifiers.PbeWithShaAnd128BitRC2Cbc.Id;
        [Obsolete("Use 'PbewithShaAnd40BitRC2Cbc' instead")]
        public static readonly string PbeSha1_RC2_40 = PkcsObjectIdentifiers.PbewithShaAnd40BitRC2Cbc.Id;

        private char[] password;
        private string algorithm;
        private int iterationCount;
        private AsymmetricKeyParameter privKey;
        private SecureRandom random;

        /**
         * Constructor for an unencrypted private key PEM object.
         *
         * @param key private key to be encoded.
         */
        public Pkcs8Generator(AsymmetricKeyParameter privKey)
        {
            this.privKey = privKey;
        }

        /**
         * Constructor for an encrypted private key PEM object.
         *
         * @param key       private key to be encoded
         * @param algorithm encryption algorithm to use
         * @param provider  provider to use
         * @throws NoSuchAlgorithmException if algorithm/mode cannot be found
         */
        public Pkcs8Generator(AsymmetricKeyParameter privKey, string algorithm)
            : this(privKey, new DerObjectIdentifier(algorithm))
        {
            this.privKey = privKey;
            this.algorithm = algorithm;
            this.iterationCount = 2048;
        }

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

        public SecureRandom SecureRandom
        {
            set { this.random = value; }
        }

        public char[] Password
        {
            set { this.password = value; }
        }

        public int IterationCount
        {
            set { this.iterationCount = value; }
        }

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
