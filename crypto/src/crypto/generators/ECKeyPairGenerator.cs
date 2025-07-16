using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Generators
{
    public class ECKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private readonly string m_algorithm;

        private ECDomainParameters m_parameters;
        private SecureRandom m_random;

        public ECKeyPairGenerator()
            : this("EC")
        {
        }

        public ECKeyPairGenerator(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            m_algorithm = ECKeyParameters.VerifyAlgorithmName(algorithm);
        }

        public void Init(KeyGenerationParameters parameters)
        {
            if (parameters is ECKeyGenerationParameters ecP)
            {
                m_parameters = ecP.DomainParameters;
            }
            else
            {
                DerObjectIdentifier oid;
                switch (parameters.Strength)
                {
                case 192:
                    oid = X9ObjectIdentifiers.Prime192v1;
                    break;
                case 224:
                    oid = SecObjectIdentifiers.SecP224r1;
                    break;
                case 239:
                    oid = X9ObjectIdentifiers.Prime239v1;
                    break;
                case 256:
                    oid = X9ObjectIdentifiers.Prime256v1;
                    break;
                case 384:
                    oid = SecObjectIdentifiers.SecP384r1;
                    break;
                case 521:
                    oid = SecObjectIdentifiers.SecP521r1;
                    break;
                default:
                    throw new InvalidParameterException("unknown key size.");
                }

                m_parameters = ECNamedDomainParameters.LookupOid(oid);
            }

            m_random = CryptoServicesRegistrar.GetSecureRandom(parameters.Random);
        }

        /**
         * Given the domain parameters this routine generates an EC key
         * pair in accordance with X9.62 section 5.2.1 pages 26, 27.
         */
        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            BigInteger d = GeneratePrivateScalar(m_parameters.N, m_random);
            var privateKey = new ECPrivateKeyParameters(m_algorithm, d, m_parameters);
            var publicKey = GetCorrespondingPublicKey(privateKey, CreateBasePointMultiplier());
            return new AsymmetricCipherKeyPair(publicKey, privateKey);
        }

        protected virtual ECMultiplier CreateBasePointMultiplier() => new FixedPointCombMultiplier();

        private static BigInteger GeneratePrivateScalar(BigInteger n, SecureRandom random)
        {
            int minWeight = n.BitLength >> 2;

            for (;;)
            {
                var d = new BigInteger(n.BitLength, random);

                if (d.CompareTo(BigInteger.One) < 0 || d.CompareTo(n) >= 0)
                    continue;

                if (WNafUtilities.GetNafWeight(d) < minWeight)
                    continue;

                return d;
            }
        }

        internal static ECPublicKeyParameters GetCorrespondingPublicKey(ECPrivateKeyParameters privateKey) =>
            GetCorrespondingPublicKey(privateKey, new FixedPointCombMultiplier());

        private static ECPublicKeyParameters GetCorrespondingPublicKey(ECPrivateKeyParameters privateKey,
            ECMultiplier multiplier)
        {
            ECDomainParameters dp = privateKey.Parameters;
            ECPoint q = multiplier.Multiply(dp.G, privateKey.D);
            return new ECPublicKeyParameters(privateKey.AlgorithmName, q, dp);
        }
    }
}
