using System;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif
using System.Security.Cryptography;
using SystemX509 = System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Security
{
    /// <summary>
    /// A class containing methods to interface the BouncyCastle world to the .NET Crypto world.
    /// </summary>
    public static class DotNetUtilities
    {
        /// <summary>
        /// Create an System.Security.Cryptography.X509Certificate from an X509Certificate Structure.
        /// </summary>
        /// <param name="x509Struct"></param>
        /// <returns>A System.Security.Cryptography.X509Certificate.</returns>
        public static SystemX509.X509Certificate ToX509Certificate(
            X509CertificateStructure x509Struct)
        {
            return new SystemX509.X509Certificate(x509Struct.GetDerEncoded());
        }

        public static SystemX509.X509Certificate ToX509Certificate(
            X509Certificate x509Cert)
        {
            return new SystemX509.X509Certificate(x509Cert.GetEncoded());
        }

        public static X509Certificate FromX509Certificate(
            SystemX509.X509Certificate x509Cert)
        {
            return new X509CertificateParser().ReadCertificate(x509Cert.GetRawCertData());
        }

        public static AsymmetricCipherKeyPair GetDsaKeyPair(DSA dsa)
        {
            return GetDsaKeyPair(dsa.ExportParameters(true));
        }

        public static AsymmetricCipherKeyPair GetDsaKeyPair(DSAParameters dp)
        {
            DsaPublicKeyParameters pubKey = GetDsaPublicKey(dp);

            DsaPrivateKeyParameters privKey = new DsaPrivateKeyParameters(
                new BigInteger(1, dp.X),
                pubKey.Parameters);

            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }

        public static DsaPublicKeyParameters GetDsaPublicKey(DSA dsa)
        {
            return GetDsaPublicKey(dsa.ExportParameters(false));
        }

        public static DsaPublicKeyParameters GetDsaPublicKey(DSAParameters dp)
        {
            DsaValidationParameters validationParameters = (dp.Seed != null)
                ? new DsaValidationParameters(dp.Seed, dp.Counter)
                : null;

            DsaParameters parameters = new DsaParameters(
                new BigInteger(1, dp.P),
                new BigInteger(1, dp.Q),
                new BigInteger(1, dp.G),
                validationParameters);

            return new DsaPublicKeyParameters(
                new BigInteger(1, dp.Y),
                parameters);
        }

#if NETCOREAPP1_0_OR_GREATER || NET47_OR_GREATER || NETSTANDARD1_6_OR_GREATER
        public static AsymmetricCipherKeyPair GetECDsaKeyPair(ECDsa ecDsa)
        {
            return GetECKeyPair("ECDSA", ecDsa.ExportParameters(true));
        }

        public static ECPublicKeyParameters GetECDsaPublicKey(ECDsa ecDsa)
        {
            return GetECPublicKey("ECDSA", ecDsa.ExportParameters(false));
        }

        public static AsymmetricCipherKeyPair GetECKeyPair(string algorithm, ECParameters ec)
        {
            ECPublicKeyParameters pubKey = GetECPublicKey(algorithm, ec);

            ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(
                pubKey.AlgorithmName,
                new BigInteger(1, ec.D),
                pubKey.Parameters);

            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }

        public static ECPublicKeyParameters GetECPublicKey(string algorithm, ECParameters ec)
        {
            X9ECParameters x9 = GetX9ECParameters(ec.Curve);
            if (x9 == null)
                throw new NotSupportedException("Unrecognized curve");

            return new ECPublicKeyParameters(
                algorithm,
                GetECPoint(x9.Curve, ec.Q),
                new ECDomainParameters(x9));
        }

        private static Math.EC.ECPoint GetECPoint(Math.EC.ECCurve curve, ECPoint point)
        {
            return curve.CreatePoint(new BigInteger(1, point.X), new BigInteger(1, point.Y));
        }

        private static X9ECParameters GetX9ECParameters(ECCurve curve)
        {
            if (!curve.IsNamed)
                throw new NotSupportedException("Only named curves are supported");

            Oid oid = curve.Oid;
            if (oid != null)
            {
                string oidValue = oid.Value;
                if (oidValue != null)
                    return ECKeyPairGenerator.FindECCurveByOid(new DerObjectIdentifier(oidValue));
            }
            return null;
        }
#endif

        public static AsymmetricCipherKeyPair GetRsaKeyPair(RSA rsa)
        {
            return GetRsaKeyPair(rsa.ExportParameters(true));
        }

        public static AsymmetricCipherKeyPair GetRsaKeyPair(RSAParameters rp)
        {
            RsaKeyParameters pubKey = GetRsaPublicKey(rp);

            RsaPrivateCrtKeyParameters privKey = new RsaPrivateCrtKeyParameters(
                pubKey.Modulus,
                pubKey.Exponent,
                new BigInteger(1, rp.D),
                new BigInteger(1, rp.P),
                new BigInteger(1, rp.Q),
                new BigInteger(1, rp.DP),
                new BigInteger(1, rp.DQ),
                new BigInteger(1, rp.InverseQ));

            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }

        public static RsaKeyParameters GetRsaPublicKey(RSA rsa)
        {
            return GetRsaPublicKey(rsa.ExportParameters(false));
        }

        public static RsaKeyParameters GetRsaPublicKey(
            RSAParameters rp)
        {
            return new RsaKeyParameters(
                false,
                new BigInteger(1, rp.Modulus),
                new BigInteger(1, rp.Exponent));
        }

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

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaKeyParameters rsaKey)
        {
            // TODO This appears to not work for private keys (when no CRT info)
            return CreateRSAProvider(ToRSAParameters(rsaKey));
        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaKeyParameters rsaKey, CspParameters csp)
        {
            // TODO This appears to not work for private keys (when no CRT info)
            return CreateRSAProvider(ToRSAParameters(rsaKey), csp);
        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaPrivateCrtKeyParameters privKey)
        {
            return CreateRSAProvider(ToRSAParameters(privKey));
        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaPrivateCrtKeyParameters privKey, CspParameters csp)
        {
            return CreateRSAProvider(ToRSAParameters(privKey), csp);
        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaPrivateKeyStructure privKey)
        {
            return CreateRSAProvider(ToRSAParameters(privKey));
        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        public static RSA ToRSA(RsaPrivateKeyStructure privKey, CspParameters csp)
        {
            return CreateRSAProvider(ToRSAParameters(privKey), csp);
        }

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

        private static byte[] ConvertRSAParametersField(BigInteger n, int size)
        {
            return BigIntegers.AsUnsignedByteArray(size, n);
        }

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
    }
}
