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
using Org.BouncyCastle.Crypto.EC;

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
#if NET9_0_OR_GREATER
            return SystemX509.X509CertificateLoader.LoadCertificate(x509Struct.GetEncoded(Asn1Encodable.Der));
#else
            return new SystemX509.X509Certificate2(x509Struct.GetEncoded(Asn1Encodable.Der));
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

        /// <summary>
        /// Create a Bouncy Castle <see cref="X509Certificate"/> from a .NET <see cref="SystemX509.X509Certificate"/>.
        /// </summary>
        /// <param name="x509Cert">The .NET certificate.</param>
        /// <returns>A Bouncy Castle <see cref="X509Certificate"/>.</returns>
        public static X509Certificate FromX509Certificate(SystemX509.X509Certificate x509Cert) =>
            new X509Certificate(x509Cert.GetRawCertData());

        /// <summary>
        /// Create a Bouncy Castle <see cref="X509Certificate"/> from a .NET <see cref="SystemX509.X509Certificate2"/>.
        /// </summary>
        /// <param name="x509Cert">The .NET certificate.</param>
        /// <returns>A Bouncy Castle <see cref="X509Certificate"/>.</returns>
        public static X509Certificate FromX509Certificate(SystemX509.X509Certificate2 x509Cert) =>
            new X509Certificate(x509Cert.RawData);

        /// <summary>
        /// Extract the <see cref="SubjectPublicKeyInfo"/> (X.509 / PKCS#8) from a .NET <see cref="SystemX509.X509Certificate2"/>.
        /// </summary>
        /// <param name="certificate">The .NET certificate.</param>
        /// <returns>A <see cref="SubjectPublicKeyInfo"/> object.</returns>
        /// <remarks>
        /// This is a convenience method that converts a .NET certificate to a Bouncy Castle certificate 
        /// and then extracts the public key information using <see cref="SubjectPublicKeyInfoFactory"/>.
        /// </remarks>
        /// <exception cref="ArgumentNullException">If <paramref name="certificate"/> is null.</exception>
        public static SubjectPublicKeyInfo GetSubjectPublicKeyInfo(SystemX509.X509Certificate2 certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));

            var bcCert = FromX509Certificate(certificate);
            return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcCert.GetPublicKey());
        }

        /// <summary>
        /// Extract the DER-encoded <see cref="SubjectPublicKeyInfo"/> bytes from a .NET <see cref="SystemX509.X509Certificate2"/>.
        /// </summary>
        /// <param name="certificate">The .NET certificate.</param>
        /// <returns>A byte array containing the DER-encoded public key info.</returns>
        /// <remarks>
        /// This is a convenience method that returns the raw DER-encoded bytes of the public key info,
        /// suitable for saving to disk or transmitting over the network.
        /// </remarks>
        /// <exception cref="ArgumentNullException">If <paramref name="certificate"/> is null.</exception>
        public static byte[] GetSubjectPublicKeyInfoDer(SystemX509.X509Certificate2 certificate)
        {
            return GetSubjectPublicKeyInfo(certificate).GetEncoded(Asn1Encodable.Der);
        }

        /// <summary>
        /// Extract a DSA key pair from a .NET <see cref="DSA"/> object.
        /// </summary>
        /// <param name="dsa">The .NET DSA object.</param>
        /// <returns>An <see cref="AsymmetricCipherKeyPair"/> containing the BC DSA keys.</returns>
        public static AsymmetricCipherKeyPair GetDsaKeyPair(DSA dsa)
        {
            return GetDsaKeyPair(dsa.ExportParameters(true));
        }

        /// <summary>
        /// Extract a DSA key pair from <see cref="DSAParameters"/>.
        /// </summary>
        /// <param name="dp">The .NET DSA parameters.</param>
        /// <returns>An <see cref="AsymmetricCipherKeyPair"/> containing the BC DSA keys.</returns>
        public static AsymmetricCipherKeyPair GetDsaKeyPair(DSAParameters dp)
        {
            DsaPublicKeyParameters pubKey = GetDsaPublicKey(dp);

            DsaPrivateKeyParameters privKey = new DsaPrivateKeyParameters(
                new BigInteger(1, dp.X),
                pubKey.Parameters);

            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }

        /// <summary>
        /// Extract DSA public key parameters from a .NET <see cref="DSA"/> object.
        /// </summary>
        /// <param name="dsa">The .NET DSA object.</param>
        /// <returns>A <see cref="DsaPublicKeyParameters"/> object.</returns>
        public static DsaPublicKeyParameters GetDsaPublicKey(DSA dsa)
        {
            return GetDsaPublicKey(dsa.ExportParameters(false));
        }

        /// <summary>
        /// Extract DSA public key parameters from <see cref="DSAParameters"/>.
        /// </summary>
        /// <param name="dp">The .NET DSA parameters.</param>
        /// <returns>A <see cref="DsaPublicKeyParameters"/> object.</returns>
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
        /// <summary>
        /// Extract an EC key pair from a .NET <see cref="ECDsa"/> object.
        /// </summary>
        /// <param name="ecDsa">The .NET ECDsa object.</param>
        /// <returns>An <see cref="AsymmetricCipherKeyPair"/> containing the BC EC keys.</returns>
        public static AsymmetricCipherKeyPair GetECDsaKeyPair(ECDsa ecDsa)
        {
            return GetECKeyPair("ECDSA", ecDsa.ExportParameters(true));
        }

        /// <summary>
        /// Extract EC public key parameters from a .NET <see cref="ECDsa"/> object.
        /// </summary>
        /// <param name="ecDsa">The .NET ECDsa object.</param>
        /// <returns>An <see cref="ECPublicKeyParameters"/> object.</returns>
        public static ECPublicKeyParameters GetECDsaPublicKey(ECDsa ecDsa)
        {
            return GetECPublicKey("ECDSA", ecDsa.ExportParameters(false));
        }

        /// <summary>
        /// Extract an EC key pair from <see cref="ECParameters"/>.
        /// </summary>
        /// <param name="algorithm">The algorithm name (e.g., "ECDSA").</param>
        /// <param name="ec">The .NET EC parameters.</param>
        /// <returns>An <see cref="AsymmetricCipherKeyPair"/> containing the BC EC keys.</returns>
        public static AsymmetricCipherKeyPair GetECKeyPair(string algorithm, ECParameters ec)
        {
            ECPublicKeyParameters pubKey = GetECPublicKey(algorithm, ec);

            ECPrivateKeyParameters privKey = new ECPrivateKeyParameters(
                pubKey.AlgorithmName,
                new BigInteger(1, ec.D),
                pubKey.Parameters);

            return new AsymmetricCipherKeyPair(pubKey, privKey);
        }

        /// <summary>
        /// Extract EC public key parameters from <see cref="ECParameters"/>.
        /// </summary>
        /// <param name="algorithm">The algorithm name (e.g., "ECDSA").</param>
        /// <param name="ec">The .NET EC parameters.</param>
        /// <returns>An <see cref="ECPublicKeyParameters"/> object.</returns>
        public static ECPublicKeyParameters GetECPublicKey(string algorithm, ECParameters ec)
        {
            X9ECParameters x9 = GetX9ECParameters(ec.Curve);
            if (x9 == null)
                throw new NotSupportedException("Unrecognized curve");

            return new ECPublicKeyParameters(
                algorithm,
                GetECPoint(x9.Curve, ec.Q),
                ECDomainParameters.FromX9ECParameters(x9));
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
                if (oidValue != null && DerObjectIdentifier.TryFromID(oidValue, out var bcOid))
                    return ECUtilities.FindECCurveByOid(bcOid);
            }
            return null;
        }
#endif

        /// <summary>
        /// Extract an RSA key pair from a .NET <see cref="RSA"/> object.
        /// </summary>
        /// <param name="rsa">The .NET RSA object.</param>
        /// <returns>An <see cref="AsymmetricCipherKeyPair"/> containing the BC RSA keys.</returns>
        public static AsymmetricCipherKeyPair GetRsaKeyPair(RSA rsa)
        {
            return GetRsaKeyPair(rsa.ExportParameters(true));
        }

        /// <summary>
        /// Extract an RSA key pair from <see cref="RSAParameters"/>.
        /// </summary>
        /// <param name="rp">The .NET RSA parameters.</param>
        /// <returns>An <see cref="AsymmetricCipherKeyPair"/> containing the BC RSA keys.</returns>
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

        /// <summary>
        /// Extract RSA public key parameters from a .NET <see cref="RSA"/> object.
        /// </summary>
        /// <param name="rsa">The .NET RSA object.</param>
        /// <returns>An <see cref="RsaKeyParameters"/> object.</returns>
        public static RsaKeyParameters GetRsaPublicKey(RSA rsa)
        {
            return GetRsaPublicKey(rsa.ExportParameters(false));
        }

        /// <summary>
        /// Extract RSA public key parameters from <see cref="RSAParameters"/>.
        /// </summary>
        /// <param name="rp">The .NET RSA parameters.</param>
        /// <returns>An <see cref="RsaKeyParameters"/> object.</returns>
        public static RsaKeyParameters GetRsaPublicKey(RSAParameters rp)
        {
            return new RsaKeyParameters(
                false,
                new BigInteger(1, rp.Modulus),
                new BigInteger(1, rp.Exponent));
        }

        /// <summary>
        /// Extract an asymmetric key pair from a .NET <see cref="AsymmetricAlgorithm"/> object.
        /// </summary>
        /// <param name="privateKey">The .NET private key object.</param>
        /// <returns>An <see cref="AsymmetricCipherKeyPair"/> containing the BC keys.</returns>
        /// <exception cref="ArgumentException">If the algorithm is not supported.</exception>
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
        /// <summary>
        /// Create a .NET <see cref="RSA"/> instance from Bouncy Castle RSA public key parameters.
        /// </summary>
        /// <param name="rsaKey">The BC RSA public key.</param>
        /// <returns>A .NET <see cref="RSA"/> instance.</returns>
        public static RSA ToRSA(RsaKeyParameters rsaKey)
        {
            return CreateRSAProvider(ToRSAParameters(rsaKey));
        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        /// <summary>
        /// Create a .NET <see cref="RSA"/> instance from Bouncy Castle RSA public key parameters.
        /// </summary>
        /// <param name="rsaKey">The BC RSA public key.</param>
        /// <param name="csp">The .NET CspParameters.</param>
        /// <returns>A .NET <see cref="RSA"/> instance.</returns>
        public static RSA ToRSA(RsaKeyParameters rsaKey, CspParameters csp)
        {
            return CreateRSAProvider(ToRSAParameters(rsaKey), csp);
        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        /// <summary>
        /// Create a .NET <see cref="RSA"/> instance from Bouncy Castle RSA private CRT parameters.
        /// </summary>
        /// <param name="privKey">The BC RSA private CRT keys.</param>
        /// <returns>A .NET <see cref="RSA"/> instance.</returns>
        public static RSA ToRSA(RsaPrivateCrtKeyParameters privKey)
        {
            return CreateRSAProvider(ToRSAParameters(privKey));
        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        /// <summary>
        /// Create a .NET <see cref="RSA"/> instance from Bouncy Castle RSA private CRT parameters and CSP info.
        /// </summary>
        /// <param name="privKey">The BC RSA private CRT keys.</param>
        /// <param name="csp">The .NET CspParameters.</param>
        /// <returns>A .NET <see cref="RSA"/> instance.</returns>
        public static RSA ToRSA(RsaPrivateCrtKeyParameters privKey, CspParameters csp)
        {
            return CreateRSAProvider(ToRSAParameters(privKey), csp);
        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        /// <summary>
        /// Create a .NET <see cref="RSA"/> instance from Bouncy Castle RSA private CRT structure.
        /// </summary>
        /// <param name="privKey">The BC RSA private CRT keys.</param>
        /// <returns>A .NET <see cref="RSA"/> instance.</returns>
        public static RSA ToRSA(RsaPrivateKeyStructure privKey)
        {
            return CreateRSAProvider(ToRSAParameters(privKey));
        }

#if NET5_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        /// <summary>
        /// Create a .NET <see cref="RSA"/> instance from Bouncy Castle RSA private CRT structure and CSP info.
        /// </summary>
        /// <param name="privKey">The BC RSA private CRT keys.</param>
        /// <param name="csp">The .NET CspParameters.</param>
        /// <returns>A .NET <see cref="RSA"/> instance.</returns>
        public static RSA ToRSA(RsaPrivateKeyStructure privKey, CspParameters csp)
        {
            return CreateRSAProvider(ToRSAParameters(privKey), csp);
        }

        /// <summary>
        /// Convert Bouncy Castle RSA public key parameters to .NET <see cref="RSAParameters"/>.
        /// </summary>
        /// <param name="rsaKey">The BC RSA key.</param>
        /// <returns>A .NET <see cref="RSAParameters"/> object.</returns>
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

        /// <summary>
        /// Convert Bouncy Castle RSA private CRT parameters to .NET <see cref="RSAParameters"/>.
        /// </summary>
        /// <param name="privKey">The BC RSA key.</param>
        /// <returns>A .NET <see cref="RSAParameters"/> object.</returns>
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

        /// <summary>
        /// Convert Bouncy Castle RSA private CRT structure to .NET <see cref="RSAParameters"/>.
        /// </summary>
        /// <param name="privKey">The BC RSA key.</param>
        /// <returns>A .NET <see cref="RSAParameters"/> object.</returns>
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
