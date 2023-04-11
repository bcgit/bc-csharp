using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.X509
{
    internal static class X509Utilities
	{
        private static readonly Dictionary<string, DerObjectIdentifier> m_algorithms =
			new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<string, Asn1Encodable> m_exParams =
			new Dictionary<string, Asn1Encodable>(StringComparer.OrdinalIgnoreCase);
		private static readonly HashSet<DerObjectIdentifier> m_noParams = new HashSet<DerObjectIdentifier>();

		static X509Utilities()
		{
			m_algorithms.Add("MD2WITHRSAENCRYPTION", PkcsObjectIdentifiers.MD2WithRsaEncryption);
			m_algorithms.Add("MD2WITHRSA", PkcsObjectIdentifiers.MD2WithRsaEncryption);
			m_algorithms.Add("MD5WITHRSAENCRYPTION", PkcsObjectIdentifiers.MD5WithRsaEncryption);
			m_algorithms.Add("MD5WITHRSA", PkcsObjectIdentifiers.MD5WithRsaEncryption);
            m_algorithms.Add("SHA1WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            m_algorithms.Add("SHA-1WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            m_algorithms.Add("SHA1WITHRSA", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            m_algorithms.Add("SHA-1WITHRSA", PkcsObjectIdentifiers.Sha1WithRsaEncryption);
            m_algorithms.Add("SHA224WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            m_algorithms.Add("SHA-224WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            m_algorithms.Add("SHA224WITHRSA", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            m_algorithms.Add("SHA-224WITHRSA", PkcsObjectIdentifiers.Sha224WithRsaEncryption);
            m_algorithms.Add("SHA256WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            m_algorithms.Add("SHA-256WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            m_algorithms.Add("SHA256WITHRSA", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            m_algorithms.Add("SHA-256WITHRSA", PkcsObjectIdentifiers.Sha256WithRsaEncryption);
            m_algorithms.Add("SHA384WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            m_algorithms.Add("SHA-384WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            m_algorithms.Add("SHA384WITHRSA", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            m_algorithms.Add("SHA-384WITHRSA", PkcsObjectIdentifiers.Sha384WithRsaEncryption);
            m_algorithms.Add("SHA512WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            m_algorithms.Add("SHA-512WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            m_algorithms.Add("SHA512WITHRSA", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            m_algorithms.Add("SHA-512WITHRSA", PkcsObjectIdentifiers.Sha512WithRsaEncryption);
            m_algorithms.Add("SHA512(224)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            m_algorithms.Add("SHA-512(224)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            m_algorithms.Add("SHA512(224)WITHRSA", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            m_algorithms.Add("SHA-512(224)WITHRSA", PkcsObjectIdentifiers.Sha512_224WithRSAEncryption);
            m_algorithms.Add("SHA512(256)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            m_algorithms.Add("SHA-512(256)WITHRSAENCRYPTION", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            m_algorithms.Add("SHA512(256)WITHRSA", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            m_algorithms.Add("SHA-512(256)WITHRSA", PkcsObjectIdentifiers.Sha512_256WithRSAEncryption);
            m_algorithms.Add("SHA1WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			m_algorithms.Add("SHA224WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			m_algorithms.Add("SHA256WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			m_algorithms.Add("SHA384WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			m_algorithms.Add("SHA512WITHRSAANDMGF1", PkcsObjectIdentifiers.IdRsassaPss);
			m_algorithms.Add("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
			m_algorithms.Add("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160);
			m_algorithms.Add("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
			m_algorithms.Add("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128);
			m_algorithms.Add("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
			m_algorithms.Add("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256);
			m_algorithms.Add("SHA1WITHDSA", X9ObjectIdentifiers.IdDsaWithSha1);
			m_algorithms.Add("DSAWITHSHA1", X9ObjectIdentifiers.IdDsaWithSha1);
			m_algorithms.Add("SHA224WITHDSA", NistObjectIdentifiers.DsaWithSha224);
			m_algorithms.Add("SHA256WITHDSA", NistObjectIdentifiers.DsaWithSha256);
			m_algorithms.Add("SHA384WITHDSA", NistObjectIdentifiers.DsaWithSha384);
			m_algorithms.Add("SHA512WITHDSA", NistObjectIdentifiers.DsaWithSha512);
			m_algorithms.Add("SHA1WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha1);
			m_algorithms.Add("ECDSAWITHSHA1", X9ObjectIdentifiers.ECDsaWithSha1);
			m_algorithms.Add("SHA224WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha224);
			m_algorithms.Add("SHA256WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha256);
			m_algorithms.Add("SHA384WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha384);
			m_algorithms.Add("SHA512WITHECDSA", X9ObjectIdentifiers.ECDsaWithSha512);
			m_algorithms.Add("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
			m_algorithms.Add("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
			m_algorithms.Add("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
			m_algorithms.Add("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);
			m_algorithms.Add("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);

			//
			// According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
			// The parameters field SHALL be NULL for RSA based signature algorithms.
			//
			m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha1);
			m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha224);
			m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha256);
			m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha384);
			m_noParams.Add(X9ObjectIdentifiers.ECDsaWithSha512);
			m_noParams.Add(X9ObjectIdentifiers.IdDsaWithSha1);
            m_noParams.Add(OiwObjectIdentifiers.DsaWithSha1);
            m_noParams.Add(NistObjectIdentifiers.DsaWithSha224);
			m_noParams.Add(NistObjectIdentifiers.DsaWithSha256);
			m_noParams.Add(NistObjectIdentifiers.DsaWithSha384);
			m_noParams.Add(NistObjectIdentifiers.DsaWithSha512);

			//
			// RFC 4491
			//
			m_noParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
			m_noParams.Add(CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);

			//
			// explicit params
			//
			AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1, DerNull.Instance);
			m_exParams.Add("SHA1WITHRSAANDMGF1", CreatePssParams(sha1AlgId, 20));

			AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha224, DerNull.Instance);
			m_exParams.Add("SHA224WITHRSAANDMGF1", CreatePssParams(sha224AlgId, 28));

			AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
			m_exParams.Add("SHA256WITHRSAANDMGF1", CreatePssParams(sha256AlgId, 32));

			AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance);
			m_exParams.Add("SHA384WITHRSAANDMGF1", CreatePssParams(sha384AlgId, 48));

			AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha512, DerNull.Instance);
			m_exParams.Add("SHA512WITHRSAANDMGF1", CreatePssParams(sha512AlgId, 64));
		}

        internal static TResult CalculateResult<TResult>(IStreamCalculator<TResult> streamCalculator,
            Asn1Encodable asn1Encodable)
        {
            using (var stream = streamCalculator.Stream)
            {
                asn1Encodable.EncodeTo(stream, Asn1Encodable.Der);
            }
            return streamCalculator.GetResult();
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

        internal static DerBitString CollectDerBitString(IBlockResult result)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            var maxResultLength = result.GetMaxResultLength();
            Span<byte> data = maxResultLength <= 512
                ? stackalloc byte[maxResultLength]
                : new byte[maxResultLength];
            int resultLength = result.Collect(data);
            data = data[..resultLength];
#else
            var data = result.Collect();
#endif

            return new DerBitString(data);
        }

        internal static DerObjectIdentifier GetAlgorithmOid(string algorithmName)
		{
			if (m_algorithms.TryGetValue(algorithmName, out var oid))
				return oid;

			return new DerObjectIdentifier(algorithmName);
		}

		internal static AlgorithmIdentifier GetSigAlgID(DerObjectIdentifier sigOid, string algorithmName)
		{
			if (m_noParams.Contains(sigOid))
				return new AlgorithmIdentifier(sigOid);

			if (m_exParams.TryGetValue(algorithmName, out var explicitParameters))
				return new AlgorithmIdentifier(sigOid, explicitParameters);

			return new AlgorithmIdentifier(sigOid, DerNull.Instance);
		}

		internal static IEnumerable<string> GetAlgNames()
		{
			return CollectionUtilities.Proxy(m_algorithms.Keys);
		}

        internal static DerBitString GenerateBitString(IStreamCalculator<IBlockResult> streamCalculator,
			Asn1Encodable asn1Encodable)
        {
            var result = CalculateResult(streamCalculator, asn1Encodable);
            return CollectDerBitString(result);
        }

        internal static DerBitString GenerateMac(IMacFactory macFactory, Asn1Encodable asn1Encodable)
        {
			return GenerateBitString(macFactory.CreateCalculator(), asn1Encodable);
        }

        internal static DerBitString GenerateSignature(ISignatureFactory signatureFactory, Asn1Encodable asn1Encodable)
        {
            return GenerateBitString(signatureFactory.CreateCalculator(), asn1Encodable);
        }

        internal static bool VerifySignature(IVerifierFactory verifierFactory, Asn1Encodable asn1Encodable,
			DerBitString signature)
        {
            var result = CalculateResult(verifierFactory.CreateCalculator(), asn1Encodable);

			// TODO[api] Use GetOctetsSpan() once IsVerified(ReadOnlySpan<byte>) is available
			return result.IsVerified(signature.GetOctets());
        }

        internal static Asn1TaggedObject TrimExtensions(int tagNo, X509Extensions exts)
        {
            Asn1Sequence extSeq = Asn1Sequence.GetInstance(exts.ToAsn1Object());
            Asn1EncodableVector extV = new Asn1EncodableVector();
			foreach (var extEntry in extSeq)
			{
				Asn1Sequence ext = Asn1Sequence.GetInstance(extEntry);

                if (!X509Extensions.AltSignatureValue.Equals(ext[0]))
                {
                    extV.Add(ext);
                }
            }

            return new DerTaggedObject(true, tagNo, new DerSequence(extV));
        }
    }
}
