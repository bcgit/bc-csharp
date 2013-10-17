using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
    public static class TlsDHUtilities
    {
        internal static readonly BigInteger One = BigInteger.ValueOf(1);
        internal static readonly BigInteger Two = BigInteger.ValueOf(2);

        public static bool AreCompatibleParameters(DHParameters a, DHParameters b)
        {
            return a.P.Equals(b.P) && a.G.Equals(b.G);
        }

        public static byte[] CalculateDHBasicAgreement(DHPublicKeyParameters publicKey, DHPrivateKeyParameters privateKey)
        {
            DHBasicAgreement basicAgreement = new DHBasicAgreement();
            basicAgreement.Init(privateKey);
            BigInteger agreementValue = basicAgreement.CalculateAgreement(publicKey);

            /*
             * RFC 5246 8.1.2. Leading bytes of Z that contain all zero bits are stripped before it is
             * used as the pre_master_secret.
             */
            return BigIntegers.AsUnsignedByteArray(agreementValue);
        }

        public static AsymmetricCipherKeyPair GenerateDHKeyPair(SecureRandom random, DHParameters dhParams)
        {
            DHBasicKeyPairGenerator dhGen = new DHBasicKeyPairGenerator();
            dhGen.Init(new DHKeyGenerationParameters(random, dhParams));
            return dhGen.GenerateKeyPair();
        }

        public static DHPrivateKeyParameters GenerateEphemeralClientKeyExchange(SecureRandom random, DHParameters dhParams, Stream output)
        {
            AsymmetricCipherKeyPair kp = GenerateDHKeyPair(random, dhParams);

            DHPublicKeyParameters dh_public = (DHPublicKeyParameters)kp.Public;
            WriteDHParameter(dh_public.Y, output);

            return (DHPrivateKeyParameters)kp.Private;
        }

        public static DHPrivateKeyParameters GenerateEphemeralServerKeyExchange(SecureRandom random, DHParameters dhParams, Stream output)
        {
            AsymmetricCipherKeyPair kp = TlsDHUtilities.GenerateDHKeyPair(random, dhParams);

            DHPublicKeyParameters dhPublicKey = (DHPublicKeyParameters)kp.Public;
            ServerDHParams paramz = new ServerDHParams(dhPublicKey);
            paramz.Encode(output);

            return (DHPrivateKeyParameters)kp.Private;
        }

        public static DHPublicKeyParameters ValidateDHPublicKey(DHPublicKeyParameters key)
        {
            BigInteger Y = key.Y;
            DHParameters paramz = key.Parameters;
            BigInteger p = paramz.P;
            BigInteger g = paramz.G;

            if (!p.IsProbablePrime(2))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            if (g.CompareTo(Two) < 0 || g.CompareTo(p.Subtract(Two)) > 0)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            if (Y.CompareTo(Two) < 0 || Y.CompareTo(p.Subtract(One)) > 0)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            // TODO See RFC 2631 for more discussion of Diffie-Hellman validation

            return key;
        }

        public static BigInteger ReadDHParameter(Stream input)
        {
            return new BigInteger(1, TlsUtilities.ReadOpaque16(input));
        }

        public static void WriteDHParameter(BigInteger x, Stream output)
        {
            TlsUtilities.WriteOpaque16(BigIntegers.AsUnsignedByteArray(x), output);
        }
    }
}