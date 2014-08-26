using System;
using System.IO;

using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class TlsDHUtilities
    {
        internal static readonly BigInteger One = BigInteger.One;
        internal static readonly BigInteger Two = BigInteger.Two;

        public static bool AreCompatibleParameters(DHParameters a, DHParameters b)
        {
            return a.P.Equals(b.P) && a.G.Equals(b.G);
        }

        public static byte[] CalculateDHBasicAgreement(DHPublicKeyParameters publicKey,
            DHPrivateKeyParameters privateKey)
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

        public static DHPrivateKeyParameters GenerateEphemeralClientKeyExchange(SecureRandom random,
            DHParameters dhParams, Stream output)
        {
            AsymmetricCipherKeyPair kp = GenerateDHKeyPair(random, dhParams);

            DHPublicKeyParameters dhPublic = (DHPublicKeyParameters)kp.Public;
            WriteDHParameter(dhPublic.Y, output);

            return (DHPrivateKeyParameters)kp.Private;
        }

        public static DHPrivateKeyParameters GenerateEphemeralServerKeyExchange(SecureRandom random,
            DHParameters dhParams, Stream output)
        {
            AsymmetricCipherKeyPair kp = GenerateDHKeyPair(random, dhParams);

            DHPublicKeyParameters dhPublic = (DHPublicKeyParameters)kp.Public;
            new ServerDHParams(dhPublic).Encode(output);

            return (DHPrivateKeyParameters)kp.Private;
        }
        
        public static DHPublicKeyParameters ValidateDHPublicKey(DHPublicKeyParameters key)
        {
            BigInteger Y = key.Y;
            DHParameters parameters = key.Parameters;
            BigInteger p = parameters.P;
            BigInteger g = parameters.G;

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
