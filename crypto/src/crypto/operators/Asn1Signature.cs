using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Crypto.Operators
{
    internal class X509Utilities
	{
        private static readonly Dictionary<string, DerObjectIdentifier> Algorithms =
            new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, Asn1Encodable> ExParams =
            new Dictionary<string, Asn1Encodable>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<DerObjectIdentifier, AlgorithmIdentifier> NoParams =
            new Dictionary<DerObjectIdentifier, AlgorithmIdentifier>();

		static X509Utilities()
		{
		    Algorithms.Add("MD2WITHRSAENCRYPTION", PkcsObjectIdentifiers.MD2WithRsaEncryption);
			Algorithms.Add("MD2WITHRSA", PkcsObjectIdentifiers.MD2WithRsaEncryption);
			Algorithms.Add("MD5WITHRSAENCRYPTION", PkcsObjectIdentifiers.MD5WithRsaEncryption);
			Algorithms.Add("MD5WITHRSA", PkcsObjectIdentifiers.MD5WithRsaEncryption);
			Algorithms.Add("SHA1WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            Algorithms.Add("SHA-1WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            Algorithms.Add("SHA1WITHRSA", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            Algorithms.Add("SHA-1WITHRSA", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            Algorithms.Add("SHA224WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            Algorithms.Add("SHA-224WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            Algorithms.Add("SHA224WITHRSA", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            Algorithms.Add("SHA-224WITHRSA", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            Algorithms.Add("SHA256WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            Algorithms.Add("SHA-256WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            Algorithms.Add("SHA256WITHRSA", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            Algorithms.Add("SHA-256WITHRSA", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            Algorithms.Add("SHA384WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            Algorithms.Add("SHA-384WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            Algorithms.Add("SHA384WITHRSA", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            Algorithms.Add("SHA-384WITHRSA", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            Algorithms.Add("SHA512WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            Algorithms.Add("SHA-512WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            Algorithms.Add("SHA512WITHRSA", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            Algorithms.Add("SHA-512WITHRSA", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            Algorithms.Add("SHA512(224)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            Algorithms.Add("SHA-512(224)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            Algorithms.Add("SHA512(224)WITHRSA", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            Algorithms.Add("SHA-512(224)WITHRSA", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            Algorithms.Add("SHA512(256)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            Algorithms.Add("SHA-512(256)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            Algorithms.Add("SHA512(256)WITHRSA", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            Algorithms.Add("SHA-512(256)WITHRSA", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            Algorithms.Add("SHA3-224WITHRSAENCRYPTION", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
            Algorithms.Add("SHA3-256WITHRSAENCRYPTION", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
            Algorithms.Add("SHA3-384WITHRSAENCRYPTION", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
            Algorithms.Add("SHA3-512WITHRSAENCRYPTION", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);
            Algorithms.Add("SHA3-224WITHRSA", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_224);
            Algorithms.Add("SHA3-256WITHRSA", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_256);
            Algorithms.Add("SHA3-384WITHRSA", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_384);
            Algorithms.Add("SHA3-512WITHRSA", NistObjectIdentifiers.IdRsassaPkcs1V15WithSha3_512);
            Algorithms.Add("SHA1WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			Algorithms.Add("SHA224WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			Algorithms.Add("SHA256WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			Algorithms.Add("SHA384WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			Algorithms.Add("SHA512WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			Algorithms.Add("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
			Algorithms.Add("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
			Algorithms.Add("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
			Algorithms.Add("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
			Algorithms.Add("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
			Algorithms.Add("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
			Algorithms.Add("SHA1WITHDSA", X9ObjectIdentifiers.IdDsaWithSha1);
			Algorithms.Add("DSAWITHSHA1", X9ObjectIdentifiers.IdDsaWithSha1);
			Algorithms.Add("SHA224WITHDSA", NistObjectIdentifiers.DsaWithSha224);
			Algorithms.Add("SHA256WITHDSA", NistObjectIdentifiers.DsaWithSha256);
			Algorithms.Add("SHA384WITHDSA", NistObjectIdentifiers.DsaWithSha384);
			Algorithms.Add("SHA512WITHDSA", NistObjectIdentifiers.DsaWithSha512);
			Algorithms.Add("SHA1WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha1);
			Algorithms.Add("ECDSAWITHSHA1", X9ObjectIdentifiers.ECDsaWithSha1);
			Algorithms.Add("SHA224WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha224);
			Algorithms.Add("SHA256WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha256);
			Algorithms.Add("SHA384WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha384);
			Algorithms.Add("SHA512WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha512);
			Algorithms.Add("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
			Algorithms.Add("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
			Algorithms.Add("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
			Algorithms.Add("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
			Algorithms.Add("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
            Algorithms.Add("GOST3411-2012-256WITHECGOST3410", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
            Algorithms.Add("GOST3411-2012-256WITHECGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
            Algorithms.Add("GOST3411-2012-512WITHECGOST3410", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
            Algorithms.Add("GOST3411-2012-512WITHECGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);

            Algorithms.Add("SHA256WITHSM2", GMObjectIdentifiers.sm2sign_with_sha256);
            Algorithms.Add("SM3WITHSM2", GMObjectIdentifiers.sm2sign_with_sm3);

            //
            // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
            // The parameters field SHALL be NULL for RSA based signature algorithms.
            //
            AddNoParams(X9ObjectIdentifiers.ECDsaWithSha1);
			AddNoParams(X9ObjectIdentifiers.ECDsaWithSha224);
			AddNoParams(X9ObjectIdentifiers.ECDsaWithSha256);
			AddNoParams(X9ObjectIdentifiers.ECDsaWithSha384);
			AddNoParams(X9ObjectIdentifiers.ECDsaWithSha512);
            AddNoParams(X9ObjectIdentifiers.IdDsaWithSha1);
            AddNoParams(OiwObjectIdentifiers.DsaWithSha1);
            AddNoParams(NistObjectIdentifiers.DsaWithSha224);
            AddNoParams(NistObjectIdentifiers.DsaWithSha256);
            AddNoParams(NistObjectIdentifiers.DsaWithSha384);
            AddNoParams(NistObjectIdentifiers.DsaWithSha512);

            //
            // RFC 4491
            //
            AddNoParams(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
			AddNoParams(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);

            //
            // explicit params
            //
            AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
            ExParams.Add("SHA1WITHRSAANDMGF1", CreatePssParams(sha1AlgId, 20));

			AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance);
            ExParams.Add("SHA224WITHRSAANDMGF1", CreatePssParams(sha224AlgId, 28));

			AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
            ExParams.Add("SHA256WITHRSAANDMGF1", CreatePssParams(sha256AlgId, 32));

			AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance);
            ExParams.Add("SHA384WITHRSAANDMGF1", CreatePssParams(sha384AlgId, 48));

			AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, DerNull.Instance);
            ExParams.Add("SHA512WITHRSAANDMGF1", CreatePssParams(sha512AlgId, 64));

            /*
             * DSA with SHA3
             */
            AddAlgorithm("SHA3-224WITHDSA", NistObjectIdentifiers.IdDsaWithSha3_224, isNoParams: true);
            AddAlgorithm("SHA3-256WITHDSA", NistObjectIdentifiers.IdDsaWithSha3_256, isNoParams: true);
            AddAlgorithm("SHA3-384WITHDSA", NistObjectIdentifiers.IdDsaWithSha3_384, isNoParams: true);
            AddAlgorithm("SHA3-512WITHDSA", NistObjectIdentifiers.IdDsaWithSha3_512, isNoParams: true);

            /*
             * ECDSA with SHA3
             */
            AddAlgorithm("SHA3-224WITHECDSA", NistObjectIdentifiers.IdEcdsaWithSha3_224, isNoParams: true);
            AddAlgorithm("SHA3-256WITHECDSA", NistObjectIdentifiers.IdEcdsaWithSha3_256, isNoParams: true);
            AddAlgorithm("SHA3-384WITHECDSA", NistObjectIdentifiers.IdEcdsaWithSha3_384, isNoParams: true);
            AddAlgorithm("SHA3-512WITHECDSA", NistObjectIdentifiers.IdEcdsaWithSha3_512, isNoParams: true);

            /*
             * EdDSA
             */
            AddAlgorithm("Ed25519", EdECObjectIdentifiers.id_Ed25519, isNoParams: true);
            AddAlgorithm("Ed448", EdECObjectIdentifiers.id_Ed448, isNoParams: true);

            /*
             * ML-DSA
             */
            foreach (MLDsaParameters mlDsa in MLDsaParameters.ByName.Values)
            {
                AddAlgorithm(mlDsa.Name, mlDsa.Oid, isNoParams: true);
            }

            /*
             * SLH-DSA
             */
            foreach (SlhDsaParameters slhDsa in SlhDsaParameters.ByName.Values)
            {
                AddAlgorithm(slhDsa.Name, slhDsa.Oid, isNoParams: true);
            }
		}

        private static void AddAlgorithm(string name, DerObjectIdentifier oid, bool isNoParams)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            Algorithms.Add(name, oid);
            if (isNoParams)
            {
                AddNoParams(oid);
            }
        }

        private static void AddNoParams(DerObjectIdentifier oid)
        {
            NoParams.Add(oid, new AlgorithmIdentifier(oid));
        }

        private static RsassaPssParameters CreatePssParams(AlgorithmIdentifier digAlgID, int saltSize)
        {
            return new RsassaPssParameters(
                digAlgID,
                new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, digAlgID),
                new DerInteger(saltSize),
                DerInteger.One);
        }

        internal static DerObjectIdentifier GetSigOid(string sigName)
		{
            if (Algorithms.TryGetValue(sigName, out var oid))
                return oid;

			return new DerObjectIdentifier(sigName);
		}

		internal static AlgorithmIdentifier GetSigAlgID(string algorithmName)
		{
            DerObjectIdentifier sigOid = X509Utilities.GetSigOid(algorithmName);

            if (NoParams.TryGetValue(sigOid, out var noParamsAlgID))
                return noParamsAlgID;

            if (ExParams.TryGetValue(algorithmName, out var explicitParameters))
                return new AlgorithmIdentifier(sigOid, explicitParameters);

			return new AlgorithmIdentifier(sigOid, DerNull.Instance);
		}

		internal static IEnumerable<string> GetSigNames()
		{
			return CollectionUtilities.Proxy(Algorithms.Keys);
		}
	}



    /// <summary>
    /// Calculator factory class for signature generation in ASN.1 based profiles that use an AlgorithmIdentifier to preserve
    /// signature algorithm details.
    /// </summary>
	public class Asn1SignatureFactory
        : ISignatureFactory
    {
        private readonly AlgorithmIdentifier m_algID;
        private readonly string m_algorithm;
        private readonly AsymmetricKeyParameter m_privateKey;
        private readonly SecureRandom m_random;

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="algorithm">The name of the signature algorithm to use.</param>
        /// <param name="privateKey">The private key to be used in the signing operation.</param>
		public Asn1SignatureFactory(string algorithm, AsymmetricKeyParameter privateKey)
            : this(algorithm, privateKey, random: null)
        {
        }

        /// <summary>
        /// Constructor which also specifies a source of randomness to be used if one is required.
        /// </summary>
        /// <param name="algorithm">The name of the signature algorithm to use.</param>
        /// <param name="privateKey">The private key to be used in the signing operation.</param>
        /// <param name="random">The source of randomness to be used in signature calculation.</param>
		public Asn1SignatureFactory(string algorithm, AsymmetricKeyParameter privateKey, SecureRandom random)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));
            if (!privateKey.IsPrivate)
                throw new ArgumentException("Key for signing must be private", nameof(privateKey));

            m_algID = X509Utilities.GetSigAlgID(algorithm);
            m_algorithm = algorithm;
            m_privateKey = privateKey;
            m_random = random;
        }

        public Asn1SignatureFactory(AlgorithmIdentifier algorithm, AsymmetricKeyParameter privateKey)
            : this(algorithm, privateKey, random: null)
        {
        }

        public Asn1SignatureFactory(AlgorithmIdentifier algorithm, AsymmetricKeyParameter privateKey,
            SecureRandom random)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey));
            if (!privateKey.IsPrivate)
                throw new ArgumentException("Key for signing must be private", nameof(privateKey));

            m_algID = algorithm;
            m_algorithm = X509SignatureUtilities.GetSignatureName(algorithm);
            m_privateKey = privateKey;
            m_random = random;
        }

        public object AlgorithmDetails => m_algID;

        public IStreamCalculator<IBlockResult> CreateCalculator()
        {
            ISigner signer = SignerUtilities.InitSigner(m_algorithm, forSigning: true, m_privateKey, m_random);
            return new DefaultSignatureCalculator(signer);
        }

        /// <summary>
        /// Allows enumeration of the signature names supported by the verifier provider.
        /// </summary>
        // TODO[api] Remove method and cleanup underlying implementation
        public static IEnumerable<string> SignatureAlgNames => X509Utilities.GetSigNames();
    }

    /// <summary>
    /// Verifier class for signature verification in ASN.1 based profiles that use an AlgorithmIdentifier to preserve
    /// signature algorithm details.
    /// </summary>
    public class Asn1VerifierFactory
        : IVerifierFactory
    {
        private readonly AlgorithmIdentifier m_algID;
        private readonly string m_algorithm;
        private readonly AsymmetricKeyParameter m_publicKey;

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="algorithm">The name of the signature algorithm to use.</param>
        /// <param name="publicKey">The public key to be used in the verification operation.</param>
        public Asn1VerifierFactory(string algorithm, AsymmetricKeyParameter publicKey)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.IsPrivate)
                throw new ArgumentException("Key for verifying must be public", nameof(publicKey));

            m_algID = X509Utilities.GetSigAlgID(algorithm);
            m_algorithm = algorithm;
            m_publicKey = publicKey;
        }

        public Asn1VerifierFactory(AlgorithmIdentifier algorithm, AsymmetricKeyParameter publicKey)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.IsPrivate)
                throw new ArgumentException("Key for verifying must be public", nameof(publicKey));

            m_algID = algorithm;
            m_algorithm = X509SignatureUtilities.GetSignatureName(algorithm);
            m_publicKey = publicKey;
        }

        public object AlgorithmDetails => m_algID;

        public IStreamCalculator<IVerifier> CreateCalculator()
        {
            ISigner verifier = SignerUtilities.InitSigner(m_algorithm, forSigning: false, m_publicKey, random: null);
            return new DefaultVerifierCalculator(verifier);
        }
    }

    /// <summary>
    /// Provider class which supports dynamic creation of signature verifiers.
    /// </summary>
	public class Asn1VerifierFactoryProvider
        : IVerifierFactoryProvider
    {
        private readonly AsymmetricKeyParameter m_publicKey;

        /// <summary>
        /// Base constructor - specify the public key to be used in verification.
        /// </summary>
        /// <param name="publicKey">The public key to be used in creating verifiers provided by this object.</param>
		public Asn1VerifierFactoryProvider(AsymmetricKeyParameter publicKey)
        {
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.IsPrivate)
                throw new ArgumentException("Key for verifying must be public", nameof(publicKey));

            m_publicKey = publicKey;
        }

        public IVerifierFactory CreateVerifierFactory(object algorithmDetails) =>
            new Asn1VerifierFactory((AlgorithmIdentifier)algorithmDetails, m_publicKey);

        /// <summary>
        /// Allows enumeration of the signature names supported by the verifier provider.
        /// </summary>
        // TODO[api] Remove method and cleanup underlying implementation
        public IEnumerable<string> SignatureAlgNames => X509Utilities.GetSigNames();
    }
}
