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
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.X509
{
    internal static class X509Utilities
	{
        private static readonly Dictionary<string, DerObjectIdentifier> m_algorithms =
			new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);

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
		}

		internal static byte[] CalculateDigest(AlgorithmIdentifier digestAlgorithm, Asn1Encodable asn1Encodable)
		{
            var digest = DigestUtilities.GetDigest(digestAlgorithm.Algorithm);
            var digestCalculator = new DefaultDigestCalculator(digest);
            var digestResult = CalculateResult(digestCalculator, asn1Encodable);
			return digestResult.Collect();
        }

        internal static byte[] CalculateDigest(IDigestFactory digestFactory, byte[] buf) =>
            CalculateDigest(digestFactory, buf, 0, buf.Length);

        internal static byte[] CalculateDigest(IDigestFactory digestFactory, byte[] buf, int off, int len)
        {
            var digestCalculator = digestFactory.CreateCalculator();
            var digestResult = CalculateResult(digestCalculator, buf, off, len);
            return digestResult.Collect();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static byte[] CalculateDigest(IDigestFactory digestFactory, ReadOnlySpan<byte> buf)
        {
            var digestCalculator = digestFactory.CreateCalculator();
            var digestResult = CalculateResult(digestCalculator, buf);
            return digestResult.Collect();
        }
#endif

        internal static byte[] CalculateDigest(IDigestFactory digestFactory, Asn1Encodable asn1Encodable)
        {
            var digestCalculator = digestFactory.CreateCalculator();
            var digestResult = CalculateResult(digestCalculator, asn1Encodable);
            return digestResult.Collect();
        }

        internal static TResult CalculateResult<TResult>(IStreamCalculator<TResult> streamCalculator, byte[] buf,
            int off, int len)
        {
            using (var stream = streamCalculator.Stream)
            {
                stream.Write(buf, off, len);
            }
            return streamCalculator.GetResult();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static TResult CalculateResult<TResult>(IStreamCalculator<TResult> streamCalculator,
            ReadOnlySpan<byte> buf)
        {
            using (var stream = streamCalculator.Stream)
            {
                stream.Write(buf);
            }
            return streamCalculator.GetResult();
        }
#endif

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
				DerInteger.One);
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

        // TODO[api] Remove (along with m_algorithms) when callers are obsoleted
        internal static IEnumerable<string> GetAlgNames() => CollectionUtilities.Proxy(m_algorithms.Keys);

        internal static DerBitString GenerateBitString(IStreamCalculator<IBlockResult> streamCalculator,
			Asn1Encodable asn1Encodable)
        {
            var result = CalculateResult(streamCalculator, asn1Encodable);
            return CollectDerBitString(result);
        }

        internal static DerBitString GenerateDigest(IDigestFactory digestFactory, Asn1Encodable asn1Encodable)
        {
            return GenerateBitString(digestFactory.CreateCalculator(), asn1Encodable);
        }

        internal static DerBitString GenerateMac(IMacFactory macFactory, Asn1Encodable asn1Encodable)
        {
			return GenerateBitString(macFactory.CreateCalculator(), asn1Encodable);
        }

        internal static DerBitString GenerateSignature(ISignatureFactory signatureFactory, Asn1Encodable asn1Encodable)
        {
            return GenerateBitString(signatureFactory.CreateCalculator(), asn1Encodable);
        }

        internal static bool VerifyMac(IMacFactory macFactory, Asn1Encodable asn1Encodable, DerBitString expected)
        {
            var result = CalculateResult(macFactory.CreateCalculator(), asn1Encodable).Collect();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Arrays.FixedTimeEquals(result, expected.GetOctetsSpan());
#else
            return Arrays.FixedTimeEquals(result, expected.GetOctets());
#endif
        }

        internal static bool VerifySignature(IVerifierFactory verifierFactory, Asn1Encodable asn1Encodable,
			DerBitString signature)
        {
            var result = CalculateResult(verifierFactory.CreateCalculator(), asn1Encodable);

			// TODO[api] Use GetOctetsSpan() once IsVerified(ReadOnlySpan<byte>) is available
			return result.IsVerified(signature.GetOctets());
        }
    }
}
