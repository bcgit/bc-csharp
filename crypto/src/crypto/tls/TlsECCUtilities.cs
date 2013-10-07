using System.Collections;
using System.IO;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;
using System;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Agreement;

namespace Org.BouncyCastle.Crypto.Tls
{

    public static class TlsECCUtils
    {
        public const ExtensionType EXT_elliptic_curves = ExtensionType.elliptic_curves;
        public const ExtensionType EXT_ec_point_formats = ExtensionType.ec_point_formats;

        private static readonly string[] curveNames = new string[] { "sect163k1", "sect163r1", "sect163r2", "sect193r1",
        "sect193r2", "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1", "sect409k1", "sect409r1",
        "sect571k1", "sect571r1", "secp160k1", "secp160r1", "secp160r2", "secp192k1", "secp192r1", "secp224k1",
        "secp224r1", "secp256k1", "secp256r1", "secp384r1", "secp521r1", };

        public static void AddSupportedEllipticCurvesExtension(IDictionary extensions, NamedCurve[] namedCurves)
        {
            extensions[EXT_elliptic_curves] = CreateSupportedEllipticCurvesExtension(namedCurves);
        }

        public static void AddSupportedPointFormatsExtension(IDictionary extensions, ECPointFormat[] ecPointFormats)
        {
            extensions[EXT_ec_point_formats] = CreateSupportedPointFormatsExtension(ecPointFormats);
        }

        public static NamedCurve[] GetSupportedEllipticCurvesExtension(IDictionary extensions)
        {
            byte[] extensionData = TlsUtilities.GetExtensionData(extensions, EXT_elliptic_curves);
            return extensionData == null ? null : ReadSupportedEllipticCurvesExtension(extensionData);
        }

        public static ECPointFormat[] GetSupportedPointFormatsExtension(IDictionary extensions)
        {
            byte[] extensionData = TlsUtilities.GetExtensionData(extensions, EXT_ec_point_formats);
            return extensionData == null ? null : ReadSupportedPointFormatsExtension(extensionData);
        }

        public static byte[] CreateSupportedEllipticCurvesExtension(NamedCurve[] namedCurves)
        {
            if (namedCurves == null || namedCurves.Length < 1)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            MemoryStream buf = new MemoryStream();
            int length = 2 * namedCurves.Length;
            TlsUtilities.CheckUint16(length);
            TlsUtilities.WriteUint16(length, buf);
            TlsUtilities.WriteUint16Array(namedCurves, buf);
            return buf.ToArray();
        }

        public static byte[] CreateSupportedPointFormatsExtension(ECPointFormat[] ecPointFormats)
        {
            if (ecPointFormats == null)
            {
                ecPointFormats = new ECPointFormat[] { ECPointFormat.uncompressed };
            }
            else if (!TlsProtocol.ArrayContains(ecPointFormats, (short)ECPointFormat.uncompressed))
            {
                /*
                 * RFC 4492 5.1. If the Supported Point Formats Extension is indeed sent, it MUST
                 * contain the value 0 (uncompressed) as one of the items in the list of point formats.
                 */

                // NOTE: We add it at the end (lowest preference)
                ECPointFormat[] tmp = new ECPointFormat[ecPointFormats.Length + 1];
                Array.Copy(ecPointFormats, 0, tmp, 0, ecPointFormats.Length);
                tmp[ecPointFormats.Length] = (short)ECPointFormat.uncompressed;

                ecPointFormats = tmp;
            }

            MemoryStream buf = new MemoryStream();
            TlsUtilities.CheckUint8(ecPointFormats.Length);
            TlsUtilities.WriteUint8(ecPointFormats.Length, buf);
            TlsUtilities.WriteUint8Array(ecPointFormats, buf);
            return buf.ToArray();
        }

        public static NamedCurve[] ReadSupportedEllipticCurvesExtension(byte[] extensionData)
        {
            if (extensionData == null)
            {
                throw new ArgumentException("'extensionData' cannot be null");
            }

            MemoryStream buf = new MemoryStream(extensionData);

            int length = TlsUtilities.ReadUint16(buf);
            if (length < 2 || (length & 1) != 0)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            NamedCurve[] namedCurves = TlsUtilities.ReadNamedCurveArray(length / 2, buf);

            TlsProtocol.AssertEmpty(buf);

            return namedCurves;
        }

        public static ECPointFormat[] ReadSupportedPointFormatsExtension(byte[] extensionData)
        {
            if (extensionData == null)
            {
                throw new ArgumentException("'extensionData' cannot be null");
            }

            MemoryStream buf = new MemoryStream(extensionData);

            short length = TlsUtilities.ReadUint8(buf);
            if (length < 1)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            ECPointFormat[] ecPointFormats = TlsUtilities.ReadECPointFormats(length, buf);

            TlsProtocol.AssertEmpty(buf);

            if (!TlsProtocol.ArrayContains(ecPointFormats, (short)ECPointFormat.uncompressed))
            {
                /*
                 * RFC 4492 5.1. If the Supported Point Formats Extension is indeed sent, it MUST
                 * contain the value 0 (uncompressed) as one of the items in the list of point formats.
                 */
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            return ecPointFormats;
        }

        public static String GetNameOfNamedCurve(NamedCurve namedCurve)
        {
            return IsSupportedNamedCurve(namedCurve) ? curveNames[(int)namedCurve - 1] : null;
        }

        public static ECDomainParameters GetParametersForNamedCurve(NamedCurve namedCurve)
        {
            String curveName = GetNameOfNamedCurve(namedCurve);
            if (curveName == null)
            {
                return null;
            }

            // Lazily created the first time a particular curve is accessed
            X9ECParameters ecP = SecNamedCurves.GetByName(curveName);

            if (ecP == null)
            {
                return null;
            }

            // It's a bit inefficient to do this conversion every time
            return new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());
        }

        public static bool HasAnySupportedNamedCurves()
        {
            return curveNames.Length > 0;
        }

        public static bool ContainsECCCipherSuites(CipherSuite[] cipherSuites)
        {
            for (int i = 0; i < cipherSuites.Length; ++i)
            {
                if (IsECCCipherSuite(cipherSuites[i]))
                {
                    return true;
                }
            }
            return false;
        }

        public static bool IsECCCipherSuite(CipherSuite cipherSuite)
        {
            switch (cipherSuite)
            {

                /*
                 * RFC 4492
                 */
                case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
                case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA:

                /*
                 * RFC 5289
                 */
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:

                /*
                 * RFC 5489
                 */
                case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
                case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
                case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
                case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:

                    return true;

                default:
                    return false;
            }
        }

        public static bool AreOnSameCurve(ECDomainParameters a, ECDomainParameters b)
        {
            // TODO Move to ECDomainParameters.Equals() or other utility method?
            return a.Curve.Equals(b.Curve) && a.G.Equals(b.G) && a.N.Equals(b.N)
                && a.H.Equals(b.H);
        }

        public static bool IsSupportedNamedCurve(NamedCurve namedCurve)
        {
            return (namedCurve > 0 && (int)namedCurve <= curveNames.Length);
        }

        public static bool IsCompressionPreferred(ECPointFormat[] ecPointFormats, short compressionFormat)
        {
            if (ecPointFormats == null)
            {
                return false;
            }
            for (int i = 0; i < ecPointFormats.Length; ++i)
            {
                ECPointFormat ecPointFormat = ecPointFormats[i];
                if (ecPointFormat == ECPointFormat.uncompressed)
                {
                    return false;
                }
                if ((short)ecPointFormat == compressionFormat)
                {
                    return true;
                }
            }
            return false;
        }

        public static byte[] SerializeECFieldElement(int fieldSize, BigInteger x)
        {
            int requiredLength = (fieldSize + 7) / 8;
            return BigIntegers.AsUnsignedByteArray(requiredLength, x);
        }

        public static byte[] SerializeECPoint(ECPointFormat[] ecPointFormats, ECPoint point)
        {
            ECCurve curve = point.Curve;

            /*
             * RFC 4492 5.7. ...an elliptic curve point in uncompressed or compressed format. Here, the
             * format MUST conform to what the server has requested through a Supported Point Formats
             * Extension if this extension was used, and MUST be uncompressed if this extension was not
             * used.
             */
            bool compressed = false;

            if (curve is F2mCurve)
            {
                compressed = IsCompressionPreferred(ecPointFormats, (short)ECPointFormat.ansiX962_compressed_char2);
            }
            else if (curve is FpCurve)
            {
                compressed = IsCompressionPreferred(ecPointFormats, (short)ECPointFormat.ansiX962_compressed_prime);
            }
            return point.GetEncoded(compressed);
        }

        public static byte[] SerializeECPublicKey(ECPointFormat[] ecPointFormats, ECPublicKeyParameters keyParameters)
        {
            return SerializeECPoint(ecPointFormats, keyParameters.Q);
        }

        public static BigInteger DeserializeECFieldElement(int fieldSize, byte[] encoding)
        {
            int requiredLength = (fieldSize + 7) / 8;
            if (encoding.Length != requiredLength)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
            return new BigInteger(1, encoding);
        }

        public static ECPoint DeserializeECPoint(ECPointFormat[] ecPointFormats, ECCurve curve, byte[] encoding)
        {
            /*
             * NOTE: Here we implicitly decode compressed or uncompressed encodings. DefaultTlsClient by
             * default is set up to advertise that we can parse any encoding so this works fine, but
             * extra checks might be needed here if that were changed.
             */
            return curve.DecodePoint(encoding);
        }

        public static ECPublicKeyParameters DeserializeECPublicKey(ECPointFormat[] ecPointFormats, ECDomainParameters curve_params,
            byte[] encoding)
        {
            try
            {
                ECPoint Y = DeserializeECPoint(ecPointFormats, curve_params.Curve, encoding);
                return new ECPublicKeyParameters(Y, curve_params);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
            }
        }

        public static byte[] CalculateECDHBasicAgreement(ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey)
        {
            ECDHBasicAgreement basicAgreement = new ECDHBasicAgreement();
            basicAgreement.Init(privateKey);
            BigInteger agreementValue = basicAgreement.CalculateAgreement(publicKey);

            /*
             * RFC 4492 5.10. Note that this octet string (Z in IEEE 1363 terminology) as output by
             * FE2OSP, the Field Element to Octet String Conversion Primitive, has constant length for
             * any given field; leading zeros found in this octet string MUST NOT be truncated.
             */
            return BigIntegers.AsUnsignedByteArray(basicAgreement.GetFieldSize(), agreementValue);
        }

        public static AsymmetricCipherKeyPair GenerateECKeyPair(SecureRandom random, ECDomainParameters ecParams)
        {
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
            keyPairGenerator.Init(new ECKeyGenerationParameters(ecParams, random));
            return keyPairGenerator.GenerateKeyPair();
        }

        public static ECPrivateKeyParameters GenerateEphemeralClientKeyExchange(SecureRandom random, ECPointFormat[] ecPointFormats,
            ECDomainParameters ecParams, Stream output)
        {
            AsymmetricCipherKeyPair kp = TlsECCUtils.GenerateECKeyPair(random, ecParams);

            ECPublicKeyParameters ecPublicKey = (ECPublicKeyParameters)kp.Public;
            WriteECPoint(ecPointFormats, ecPublicKey.Q, output);

            return (ECPrivateKeyParameters)kp.Private;
        }

        public static ECPublicKeyParameters ValidateECPublicKey(ECPublicKeyParameters key)
        {
            // TODO Check RFC 4492 for validation
            return key;
        }

        public static int ReadECExponent(int fieldSize, Stream input)
        {
            BigInteger K = ReadECParameter(input);
            if (K.BitLength < 32)
            {
                int k = K.IntValue;
                if (k > 0 && k < fieldSize)
                {
                    return k;
                }
            }
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        public static BigInteger ReadECFieldElement(int fieldSize, Stream input)
        {
            return DeserializeECFieldElement(fieldSize, TlsUtilities.ReadOpaque8(input));
        }

        public static BigInteger ReadECParameter(Stream input)
        {
            // TODO Are leading zeroes okay here?
            return new BigInteger(1, TlsUtilities.ReadOpaque8(input));
        }

        public static ECDomainParameters ReadECParameters(NamedCurve[] namedCurves, ECPointFormat[] ecPointFormats, Stream input)
        {
            try
            {
                short curveType = TlsUtilities.ReadUint8(input);

                switch (curveType)
                {
                    case (short)ECCurveType.explicit_prime:
                        {
                            BigInteger prime_p = ReadECParameter(input);
                            BigInteger a = ReadECFieldElement(prime_p.BitLength, input);
                            BigInteger b = ReadECFieldElement(prime_p.BitLength, input);
                            ECCurve curve = new FpCurve(prime_p, a, b);
                            ECPoint pbase = DeserializeECPoint(ecPointFormats, curve, TlsUtilities.ReadOpaque8(input));
                            BigInteger order = ReadECParameter(input);
                            BigInteger cofactor = ReadECParameter(input);
                            return new ECDomainParameters(curve, pbase, order, cofactor);
                        }
                    case (short)ECCurveType.explicit_char2:
                        {
                            int m = TlsUtilities.ReadUint16(input);
                            short basis = TlsUtilities.ReadUint8(input);
                            ECCurve curve;
                            switch (basis)
                            {
                                case ECBasisType.ec_basis_trinomial:
                                    {
                                        int k = ReadECExponent(m, input);
                                        BigInteger a = ReadECFieldElement(m, input);
                                        BigInteger b = ReadECFieldElement(m, input);
                                        curve = new F2mCurve(m, k, a, b);
                                        break;
                                    }
                                case (short)ECBasisType.ec_basis_pentanomial:
                                    {
                                        int k1 = ReadECExponent(m, input);
                                        int k2 = ReadECExponent(m, input);
                                        int k3 = ReadECExponent(m, input);
                                        BigInteger a = ReadECFieldElement(m, input);
                                        BigInteger b = ReadECFieldElement(m, input);
                                        curve = new F2mCurve(m, k1, k2, k3, a, b);
                                        break;
                                    }
                                default:
                                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                            }
                            ECPoint pbase = DeserializeECPoint(ecPointFormats, curve, TlsUtilities.ReadOpaque8(input));
                            BigInteger order = ReadECParameter(input);
                            BigInteger cofactor = ReadECParameter(input);
                            return new ECDomainParameters(curve, pbase, order, cofactor);
                        }
                    case (short)ECCurveType.named_curve:
                        {
                            NamedCurve namedCurve = (NamedCurve)TlsUtilities.ReadUint16(input);
                            if (!NamedCurveHelper.RefersToASpecificNamedCurve(namedCurve))
                            {
                                /*
                                 * RFC 4492 5.4. All those values of NamedCurve are allowed that refer to a
                                 * specific curve. Values of NamedCurve that indicate support for a class of
                                 * explicitly defined curves are not allowed here [...].
                                 */
                                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                            }

                            if (!TlsProtocol.ArrayContains(namedCurves, namedCurve))
                            {
                                /*
                                 * RFC 4492 4. [...] servers MUST NOT negotiate the use of an ECC cipher suite
                                 * unless they can complete the handshake while respecting the choice of curves
                                 * and compression techniques specified by the client.
                                 */
                                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                            }

                            return TlsECCUtils.GetParametersForNamedCurve(namedCurve);
                        }
                    default:
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter, e);
            }
        }

        public static void WriteECExponent(int k, Stream output)
        {
            BigInteger K = BigInteger.ValueOf(k);
            WriteECParameter(K, output);
        }

        public static void WriteECFieldElement(int fieldSize, BigInteger x, Stream output)
        {
            TlsUtilities.WriteOpaque8(SerializeECFieldElement(fieldSize, x), output);
        }

        public static void WriteECParameter(BigInteger x, Stream output)
        {
            TlsUtilities.WriteOpaque8(BigIntegers.AsUnsignedByteArray(x), output);
        }

        public static void WriteExplicitECParameters(ECPointFormat[] ecPointFormats, ECDomainParameters ecParameters, Stream output)
        {
            ECCurve curve = ecParameters.Curve;
            if (curve is FpCurve)
            {
                TlsUtilities.WriteUint8((short)ECCurveType.explicit_prime, output);

                FpCurve fp = (FpCurve)curve;
                WriteECParameter(fp.Q, output);
            }
            else if (curve is F2mCurve)
            {
                TlsUtilities.WriteUint8((short)ECCurveType.explicit_char2, output);

                F2mCurve f2m = (F2mCurve)curve;
                int m = f2m.M;
                TlsUtilities.CheckUint16(m);
                TlsUtilities.WriteUint16(m, output);

                if (f2m.IsTrinomial())
                {
                    TlsUtilities.WriteUint8(ECBasisType.ec_basis_trinomial, output);
                    WriteECExponent(f2m.K1, output);
                }
                else
                {
                    TlsUtilities.WriteUint8(ECBasisType.ec_basis_pentanomial, output);
                    WriteECExponent(f2m.K1, output);
                    WriteECExponent(f2m.K2, output);
                    WriteECExponent(f2m.K3, output);
                }

            }
            else
            {
                throw new ArgumentException("'ecParameters' not a known curve type");
            }

            WriteECFieldElement(curve.FieldSize, curve.A.ToBigInteger(), output);
            WriteECFieldElement(curve.FieldSize, curve.B.ToBigInteger(), output);
            TlsUtilities.WriteOpaque8(SerializeECPoint(ecPointFormats, ecParameters.G), output);
            WriteECParameter(ecParameters.N, output);
            WriteECParameter(ecParameters.H, output);
        }

        public static void WriteECPoint(ECPointFormat[] ecPointFormats, ECPoint point, Stream output)
        {
            TlsUtilities.WriteOpaque8(TlsECCUtils.SerializeECPoint(ecPointFormats, point), output);
        }

        public static void WriteNamedECParameters(NamedCurve namedCurve, Stream output)
        {
            if (!NamedCurveHelper.RefersToASpecificNamedCurve(namedCurve))
            {
                /*
                 * RFC 4492 5.4. All those values of NamedCurve are allowed that refer to a specific
                 * curve. Values of NamedCurve that indicate support for a class of explicitly defined
                 * curves are not allowed here [...].
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            TlsUtilities.WriteUint8((byte)ECCurveType.named_curve, output);
            TlsUtilities.CheckUint16((short)namedCurve);
            TlsUtilities.WriteUint16((short)namedCurve, output);
        }
    }
}