using System;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif
using System.Security.Cryptography;

using SystemX509 = System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

#if NETCOREAPP1_0_OR_GREATER || NET47_OR_GREATER || NETSTANDARD1_6_OR_GREATER
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
#endif

namespace Org.BouncyCastle.Security
{
    /// <summary>
    /// A class containing methods to interface the BouncyCastle world to the .NET Crypto world.
    /// </summary>
    public static class DotNetUtilities
    {
        /// <summary>
        /// Create an System.Security.Cryptography.X509Certificate from an X509CertificateStructure.
        /// </summary>
        /// <param name="x509Struct"></param>
        /// <returns>A System.Security.Cryptography.X509Certificate.</returns>
        // TODO[api] Change return type to X509Certificate2
#if NET5_0_OR_GREATER
        [UnsupportedOSPlatform("browser")]
#endif
        public static SystemX509.X509Certificate ToX509Certificate(X509CertificateStructure x509Struct)
        {
            byte[] data = x509Struct.GetEncoded(Asn1Encodable.Der);
#if NET9_0_OR_GREATER
            return SystemX509.X509CertificateLoader.LoadCertificate(data);
#else
            return new SystemX509.X509Certificate2(data);
#endif
        }

        /// <summary>
        /// Create an System.Security.Cryptography.X509Certificate from an X509Certificate.
        /// </summary>
        /// <param name="x509Cert"></param>
        /// <returns>A System.Security.Cryptography.X509Certificate.</returns>
        // TODO[api] Change return type to X509Certificate2
#if NET5_0_OR_GREATER
        [UnsupportedOSPlatform("browser")]
#endif
        public static SystemX509.X509Certificate ToX509Certificate(X509Certificate x509Cert) =>
            ToX509Certificate(x509Cert.CertificateStructure);

        public static X509Certificate FromX509Certificate(SystemX509.X509Certificate x509Cert) =>
            new X509Certificate(x509Cert.GetRawCertData());

        public static X509Certificate FromX509Certificate(SystemX509.X509Certificate2 x509Cert) =>
            new X509Certificate(x509Cert.RawData);

        public static AsymmetricCipherKeyPair GetDsaKeyPair(DSA dsa) => GetDsaKeyPair(dsa.ExportParameters(true));

        public static AsymmetricCipherKeyPair GetDsaKeyPair(DSAParameters dp)
        {
            var publicKey = GetDsaPublicKey(dp);
            var privateKey = new DsaPrivateKeyParameters(BigNat(dp.X), publicKey.Parameters);
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        public static DsaPublicKeyParameters GetDsaPublicKey(DSA dsa) => GetDsaPublicKey(dsa.ExportParameters(false));

        public static DsaPublicKeyParameters GetDsaPublicKey(DSAParameters dp)
        {
            var validationParameters = (dp.Seed != null)
                ? new DsaValidationParameters(dp.Seed, dp.Counter)
                : null;
            var parameters = new DsaParameters(BigNat(dp.P), BigNat(dp.Q), BigNat(dp.G), validationParameters);
            return new DsaPublicKeyParameters(BigNat(dp.Y), parameters);
        }

#if NETCOREAPP1_0_OR_GREATER || NET47_OR_GREATER || NETSTANDARD1_6_OR_GREATER
        public static AsymmetricCipherKeyPair GetECDsaKeyPair(ECDsa ecDsa) =>
            GetECKeyPair("ECDSA", ecDsa.ExportParameters(true));

        public static ECPublicKeyParameters GetECDsaPublicKey(ECDsa ecDsa) =>
            GetECPublicKey("ECDSA", ecDsa.ExportParameters(false));

        public static AsymmetricCipherKeyPair GetECKeyPair(string algorithm, ECParameters ec)
        {
            var publicKey = GetECPublicKey(algorithm, ec);
            var privateKey = new ECPrivateKeyParameters(publicKey.AlgorithmName, BigNat(ec.D), publicKey.Parameters);
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        public static ECPublicKeyParameters GetECPublicKey(string algorithm, ECParameters ec)
        {
            var x9 = GetX9ECParameters(ec.Curve) ?? throw new NotSupportedException("Unrecognized curve");
            var q = GetECPoint(x9.Curve, ec.Q);
            var parameters = ECDomainParameters.FromX9ECParameters(x9);
            return new ECPublicKeyParameters(algorithm, q, parameters);
        }

        private static Math.EC.ECPoint GetECPoint(Math.EC.ECCurve curve, ECPoint point) =>
            curve.CreatePoint(BigNat(point.X), BigNat(point.Y));

        private static X9ECParameters GetX9ECParameters(ECCurve curve)
        {
            if (!curve.IsNamed)
                throw new NotSupportedException("Only named curves are supported");

            Oid oid = curve.Oid;
            if (oid != null)
            {
                string oidValue = oid.Value;
                if (oidValue != null && DerObjectIdentifier.TryFromID(oidValue, out var bcOid))
                    return ECUtilities.FindECCurveByOid(bcOid);
            }
            return null;
        }
#endif

        public static AsymmetricCipherKeyPair GetRsaKeyPair(RSA rsa) => GetRsaKeyPair(rsa.ExportParameters(true));

        public static AsymmetricCipherKeyPair GetRsaKeyPair(RSAParameters rp)
        {
            var publicKey = GetRsaPublicKey(rp);
            var privateKey = new RsaPrivateCrtKeyParameters(
                publicKey.Modulus,
                publicKey.Exponent,
                BigNat(rp.D),
                BigNat(rp.P),
                BigNat(rp.Q),
                BigNat(rp.DP),
                BigNat(rp.DQ),
                BigNat(rp.InverseQ));
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        public static RsaKeyParameters GetRsaPublicKey(RSA rsa) => GetRsaPublicKey(rsa.ExportParameters(false));

        public static RsaKeyParameters GetRsaPublicKey(RSAParameters rp) =>
            new RsaKeyParameters(false, BigNat(rp.Modulus), BigNat(rp.Exponent));

        public static AsymmetricCipherKeyPair GetKeyPair(AsymmetricAlgorithm privateKey)
        {
            if (privateKey is DSA dsa)
                return GetDsaKeyPair(dsa);

#if NETCOREAPP1_0_OR_GREATER || NET47_OR_GREATER || NETSTANDARD1_6_OR_GREATER
            if (privateKey is ECDsa ecDsa)
                return GetECDsaKeyPair(ecDsa);
#endif

            if (privateKey is RSA rsa)
                return GetRsaKeyPair(rsa);

            throw new ArgumentException("Unsupported algorithm specified", nameof(privateKey));
        }

        // TODO This appears to not work for private keys (when no CRT info)
#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaKeyParameters rsaKey) => CreateRSAProvider(ToRSAParameters(rsaKey));

        // TODO This appears to not work for private keys (when no CRT info)
#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaKeyParameters rsaKey, CspParameters csp) =>
            CreateRSAProvider(ToRSAParameters(rsaKey), csp);

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaPrivateCrtKeyParameters privKey) => CreateRSAProvider(ToRSAParameters(privKey));

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaPrivateCrtKeyParameters privKey, CspParameters csp) =>
            CreateRSAProvider(ToRSAParameters(privKey), csp);

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaPrivateKeyStructure privKey) => CreateRSAProvider(ToRSAParameters(privKey));

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaPrivateKeyStructure privKey, CspParameters csp) =>
            CreateRSAProvider(ToRSAParameters(privKey), csp);

        public static RSAParameters ToRSAParameters(RsaKeyParameters rsaKey)
        {
            RSAParameters rp = new RSAParameters();
            rp.Modulus = rsaKey.Modulus.ToByteArrayUnsigned();
            if (rsaKey.IsPrivate)
                rp.D = ConvertRSAParametersField(rsaKey.Exponent, rp.Modulus.Length);
            else
                rp.Exponent = rsaKey.Exponent.ToByteArrayUnsigned();
            return rp;
        }

        public static RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
        {
            RSAParameters rp = new RSAParameters();
            rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
            rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
            rp.P = privKey.P.ToByteArrayUnsigned();
            rp.Q = privKey.Q.ToByteArrayUnsigned();
            rp.D = ConvertRSAParametersField(privKey.Exponent, rp.Modulus.Length);
            rp.DP = ConvertRSAParametersField(privKey.DP, rp.P.Length);
            rp.DQ = ConvertRSAParametersField(privKey.DQ, rp.Q.Length);
            rp.InverseQ = ConvertRSAParametersField(privKey.QInv, rp.Q.Length);
            return rp;
        }

        public static RSAParameters ToRSAParameters(RsaPrivateKeyStructure privKey)
        {
            RSAParameters rp = new RSAParameters();
            rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
            rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
            rp.P = privKey.Prime1.ToByteArrayUnsigned();
            rp.Q = privKey.Prime2.ToByteArrayUnsigned();
            rp.D = ConvertRSAParametersField(privKey.PrivateExponent, rp.Modulus.Length);
            rp.DP = ConvertRSAParametersField(privKey.Exponent1, rp.P.Length);
            rp.DQ = ConvertRSAParametersField(privKey.Exponent2, rp.Q.Length);
            rp.InverseQ = ConvertRSAParametersField(privKey.Coefficient, rp.Q.Length);
            return rp;
        }

        private static byte[] ConvertRSAParametersField(BigInteger n, int size) =>
            BigIntegers.AsUnsignedByteArray(size, n);

        // TODO Why do we use CspParameters instead of just RSA.Create in methods below?
//        private static RSA CreateRSA(RSAParameters rp)
//        {
//#if NETCOREAPP2_0_OR_GREATER || NET472_OR_GREATER || NETSTANDARD2_1_OR_GREATER
//            return RSA.Create(rp);
//#else
//            var rsa = RSA.Create();
//            rsa.ImportParameters(rp);
//            return rsa;
//#endif
//        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        private static RSACryptoServiceProvider CreateRSAProvider(RSAParameters rp)
        {
            CspParameters csp = new CspParameters();
            csp.KeyContainerName = string.Format("BouncyCastle-{0}", Guid.NewGuid());
            return CreateRSAProvider(rp, csp);
        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        private static RSACryptoServiceProvider CreateRSAProvider(RSAParameters rp, CspParameters csp)
        {
            RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider(csp);
            rsaCsp.ImportParameters(rp);
            return rsaCsp;
        }

        private static BigInteger BigNat(byte[] data) => new BigInteger(1, data);
    }
}
