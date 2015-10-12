using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Operators
{
	internal class X509Utilities
	{
		private static readonly IDictionary algorithms = Platform.CreateHashtable();
		private static readonly IDictionary exParams = Platform.CreateHashtable();
		private static readonly ISet        noParams = new HashSet();

		static X509Utilities()
		{
			algorithms.Add("MD2WITHRSAENCRYPTION", PkcsObjectIdentifiers.MD2WithRsaEncryption);
			algorithms.Add("MD2WITHRSA", PkcsObjectIdentifiers.MD2WithRsaEncryption);
			algorithms.Add("MD5WITHRSAENCRYPTION", PkcsObjectIdentifiers.MD5WithRsaEncryption);
			algorithms.Add("MD5WITHRSA", PkcsObjectIdentifiers.MD5WithRsaEncryption);
			algorithms.Add("SHA1WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
			algorithms.Add("SHA1WITHRSA", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
			algorithms.Add("SHA224WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
			algorithms.Add("SHA224WITHRSA", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
			algorithms.Add("SHA256WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
			algorithms.Add("SHA256WITHRSA", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
			algorithms.Add("SHA384WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
			algorithms.Add("SHA384WITHRSA", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
			algorithms.Add("SHA512WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
			algorithms.Add("SHA512WITHRSA", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
			algorithms.Add("SHA1WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			algorithms.Add("SHA224WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			algorithms.Add("SHA256WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			algorithms.Add("SHA384WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			algorithms.Add("SHA512WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			algorithms.Add("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
			algorithms.Add("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
			algorithms.Add("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
			algorithms.Add("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
			algorithms.Add("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
			algorithms.Add("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
			algorithms.Add("SHA1WITHDSA", X9ObjectIdentifiers.IdDsaWithSha1);
			algorithms.Add("DSAWITHSHA1", X9ObjectIdentifiers.IdDsaWithSha1);
			algorithms.Add("SHA224WITHDSA", NistObjectIdentifiers.DsaWithSha224);
			algorithms.Add("SHA256WITHDSA", NistObjectIdentifiers.DsaWithSha256);
			algorithms.Add("SHA384WITHDSA", NistObjectIdentifiers.DsaWithSha384);
			algorithms.Add("SHA512WITHDSA", NistObjectIdentifiers.DsaWithSha512);
			algorithms.Add("SHA1WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha1);
			algorithms.Add("ECDSAWITHSHA1", X9ObjectIdentifiers.ECDsaWithSha1);
			algorithms.Add("SHA224WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha224);
			algorithms.Add("SHA256WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha256);
			algorithms.Add("SHA384WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha384);
			algorithms.Add("SHA512WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha512);
			algorithms.Add("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
			algorithms.Add("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
			algorithms.Add("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
			algorithms.Add("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
			algorithms.Add("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);

			//
			// According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
			// The parameters field SHALL be NULL for RSA based signature algorithms.
			//
			noParams.Add(X9ObjectIdentifiers.ECDsaWithSha1);
			noParams.Add(X9ObjectIdentifiers.ECDsaWithSha224);
			noParams.Add(X9ObjectIdentifiers.ECDsaWithSha256);
			noParams.Add(X9ObjectIdentifiers.ECDsaWithSha384);
			noParams.Add(X9ObjectIdentifiers.ECDsaWithSha512);
			noParams.Add(X9ObjectIdentifiers.IdDsaWithSha1);
			noParams.Add(NistObjectIdentifiers.DsaWithSha224);
			noParams.Add(NistObjectIdentifiers.DsaWithSha256);
			noParams.Add(NistObjectIdentifiers.DsaWithSha384);
			noParams.Add(NistObjectIdentifiers.DsaWithSha512);

			//
			// RFC 4491
			//
			noParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
			noParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);

			//
			// explicit params
			//
			AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
			exParams.Add("SHA1WITHRSAANDMGF1", CreatePssParams(sha1AlgId, 20));

			AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance);
			exParams.Add("SHA224WITHRSAANDMGF1", CreatePssParams(sha224AlgId, 28));

			AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
			exParams.Add("SHA256WITHRSAANDMGF1", CreatePssParams(sha256AlgId, 32));

			AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance);
			exParams.Add("SHA384WITHRSAANDMGF1", CreatePssParams(sha384AlgId, 48));

			AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, DerNull.Instance);
			exParams.Add("SHA512WITHRSAANDMGF1", CreatePssParams(sha512AlgId, 64));
		}

		private static RsassaPssParameters CreatePssParams(
			AlgorithmIdentifier	hashAlgId,
			int					saltSize)
		{
			return new RsassaPssParameters(
				hashAlgId,
				new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, hashAlgId),
				new DerInteger(saltSize),
				new DerInteger(1));
		}

		internal static DerObjectIdentifier GetAlgorithmOid(
			string algorithmName)
		{
			algorithmName = Platform.ToUpperInvariant(algorithmName);

			if (algorithms.Contains(algorithmName))
			{
				return (DerObjectIdentifier) algorithms[algorithmName];
			}

			return new DerObjectIdentifier(algorithmName);
		}

		internal static AlgorithmIdentifier GetSigAlgID(
			DerObjectIdentifier sigOid,
			string				algorithmName)
		{
			if (noParams.Contains(sigOid))
			{
				return new AlgorithmIdentifier(sigOid);
			}

			algorithmName = Platform.ToUpperInvariant(algorithmName);

			if (exParams.Contains(algorithmName))
			{
				return new AlgorithmIdentifier(sigOid, (Asn1Encodable) exParams[algorithmName]);
			}

			return new AlgorithmIdentifier(sigOid, DerNull.Instance);
		}

		internal static IEnumerable GetAlgNames()
		{
			return new EnumerableProxy(algorithms.Keys);
		}
	}

	internal class SignerBucket
		: Stream
	{
		protected readonly ISigner signer;

		public SignerBucket(
			ISigner	signer)
		{
			this.signer = signer;
		}

		public override int Read(
			byte[]	buffer,
			int		offset,
			int		count)
		{
			throw new NotImplementedException ();
		}

		public override int ReadByte()
		{
			throw new NotImplementedException ();
		}

		public override void Write(
			byte[]	buffer,
			int		offset,
			int		count)
		{
			if (count > 0)
			{
				signer.BlockUpdate(buffer, offset, count);
			}
		}

		public override void WriteByte(
			byte b)
		{
			signer.Update(b);
		}

		public override bool CanRead
		{
			get { return false; }
		}

		public override bool CanWrite
		{
			get { return true; }
		}

		public override bool CanSeek
		{
			get { return false; }
		}

		public override long Length
		{
			get { return 0; }
		}

		public override long Position
		{
			get { throw new NotImplementedException (); }
			set { throw new NotImplementedException (); }
		}

		public override void Close()
		{
		}

		public override  void Flush()
		{
		}

		public override long Seek(
			long		offset,
			SeekOrigin	origin)
		{
			throw new NotImplementedException ();
		}

		public override void SetLength(
			long length)
		{
			throw new NotImplementedException ();
		}
	}

    /// <summary>
    /// Calculator class for signature generation in ASN.1 based profiles that use an AlgorithmIdentifier to preserve
    /// signature algorithm details.
    /// </summary>
	public class Asn1SignatureCalculator: ISignatureCalculator<AlgorithmIdentifier>
	{
		private readonly AlgorithmIdentifier algID;
		private readonly ISigner sig;

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="algorithm">The name of the signature algorithm to use.</param>
        /// <param name="privateKey">The private key to be used in the signing operation.</param>
		public Asn1SignatureCalculator (String algorithm, AsymmetricKeyParameter privateKey): this(algorithm, privateKey, null)
		{
		}

        /// <summary>
        /// Constructor which also specifies a source of randomness to be used if one is required.
        /// </summary>
        /// <param name="algorithm">The name of the signature algorithm to use.</param>
        /// <param name="privateKey">The private key to be used in the signing operation.</param>
        /// <param name="random">The source of randomness to be used in signature calculation.</param>
		public Asn1SignatureCalculator (String algorithm, AsymmetricKeyParameter privateKey, SecureRandom random)
		{
			DerObjectIdentifier sigOid = X509Utilities.GetAlgorithmOid (algorithm);

			this.sig = SignerUtilities.GetSigner(algorithm);

			if (random != null)
			{
				sig.Init(true, new ParametersWithRandom(privateKey, random));
			}
			else
			{
				sig.Init(true, privateKey);
			}

			this.algID = X509Utilities.GetSigAlgID (sigOid, algorithm);
		}

		public AlgorithmIdentifier AlgorithmDetails
		{
			get { return this.algID; }
		}

		public Stream GetSignatureUpdater ()
		{
			return new SignerBucket (sig);
		}

		public Stream GetSignatureUpdatingStream (Stream stream)
		{
			if (stream.CanRead && stream.CanWrite) {
				throw new ArgumentException ("cannot use read/write stream");
			}

			if (stream.CanRead) {
				return new SignerStream (stream, sig, null);
			} else {
				return new SignerStream (stream, null, sig);
			}
		}

		public byte[] Signature()
		{
			return sig.GenerateSignature ();
		}

		public int Signature(byte[] destination, int off)
		{
			byte[] sigBytes = Signature ();

			Array.Copy (sigBytes, 0, destination, off, sigBytes.Length);

			return sigBytes.Length;
		}

        /// <summary>
        /// Allows enumeration of the signature names supported by the verifier provider.
        /// </summary>
        public static IEnumerable SignatureAlgNames
        {
            get { return X509Utilities.GetAlgNames(); }
        }
    }

    /// <summary>
    /// Verifier class for signature verification in ASN.1 based profiles that use an AlgorithmIdentifier to preserve
    /// signature algorithm details.
    /// </summary>
    public class Asn1SignatureVerifier: ISignatureVerifier<AlgorithmIdentifier>
	{
		private readonly AlgorithmIdentifier algID;
		private readonly ISigner sig;

        /// <summary>
        /// Base constructor.
        /// </summary>
        /// <param name="algorithm">The name of the signature algorithm to use.</param>
        /// <param name="publicKey">The public key to be used in the verification operation.</param>
        public Asn1SignatureVerifier (String algorithm, AsymmetricKeyParameter publicKey)
		{
			DerObjectIdentifier sigOid = X509Utilities.GetAlgorithmOid (algorithm);

			this.sig = SignerUtilities.GetSigner(algorithm);

			sig.Init(false, publicKey);

			this.algID = X509Utilities.GetSigAlgID (sigOid, algorithm);
		}

		public Asn1SignatureVerifier (AlgorithmIdentifier algorithm, AsymmetricKeyParameter publicKey)
		{
			DerObjectIdentifier sigOid = algorithm.Algorithm;

			this.sig = SignerUtilities.GetSigner(sigOid);

			sig.Init(false, publicKey);

			this.algID = algorithm;
		}

		public AlgorithmIdentifier AlgorithmDetails
		{
			get { return this.algID; }
		}

		public Stream GetVerifierUpdater ()
		{
			return new SignerBucket (sig);
		}

		public Stream GetVerifierUpdatingStream (Stream stream)
		{
			if (stream.CanRead && stream.CanWrite) {
				throw new ArgumentException ("cannot use read/write stream");
			}

			if (stream.CanRead) {
				return new SignerStream (stream, sig, null);
			} else {
				return new SignerStream (stream, null, sig);
			}
		}

		public bool IsVerified(byte[] signature)
		{
			return sig.VerifySignature(signature);
		}

		public bool IsVerified(byte[] signature, int off, int length)
		{
			byte[] sigBytes = new byte[length];

			Array.Copy (signature, 0, sigBytes, off, sigBytes.Length);

			return sig.VerifySignature(signature);
		}
	}

    /// <summary>
    /// Provider class which supports dynamic creation of signature verifiers.
    /// </summary>
	public class Asn1SignatureVerifierProvider: ISignatureVerifierProvider<AlgorithmIdentifier>
	{
		private readonly AsymmetricKeyParameter publicKey;

        /// <summary>
        /// Base constructor - specify the public key to be used in verification.
        /// </summary>
        /// <param name="publicKey">The public key to be used in creating verifiers provided by this object.</param>
		public Asn1SignatureVerifierProvider(AsymmetricKeyParameter publicKey)
		{
			this.publicKey = publicKey;
		}

		public ISignatureVerifier<AlgorithmIdentifier> CreateSignatureVerifier(AlgorithmIdentifier algorithmDetails)
		{
			return new Asn1SignatureVerifier (algorithmDetails, publicKey);
		}

		/// <summary>
		/// Allows enumeration of the signature names supported by the verifier provider.
		/// </summary>
		public IEnumerable SignatureAlgNames
		{
			get { return X509Utilities.GetAlgNames(); }
		}
	}
}

