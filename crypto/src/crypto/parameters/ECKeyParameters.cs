using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public abstract class ECKeyParameters
        : AsymmetricKeyParameter
    {
        // NB: Use a Dictionary so we can lookup the upper case version
        private static readonly Dictionary<string, string> Algorithms =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "EC", "EC" },
            { "ECDSA", "ECDSA" },
            { "ECDH", "ECDH" },
            { "ECDHC", "ECDHC" },
            { "ECGOST3410", "ECGOST3410" },
            { "ECMQV", "ECMQV" },
        };

        private readonly string m_algorithm;
        private readonly ECDomainParameters m_parameters;

        protected ECKeyParameters(string algorithm, bool isPrivate, ECDomainParameters parameters)
            : base(isPrivate)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));

            m_algorithm = VerifyAlgorithmName(algorithm);
            m_parameters = parameters;
        }

        protected ECKeyParameters(string algorithm, bool isPrivate, DerObjectIdentifier publicKeyParamSet)
            : base(isPrivate)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (publicKeyParamSet == null)
                throw new ArgumentNullException(nameof(publicKeyParamSet));

            m_algorithm = VerifyAlgorithmName(algorithm);
            m_parameters = ECNamedDomainParameters.LookupOid(oid: publicKeyParamSet);
        }

        public string AlgorithmName => m_algorithm;

        public ECDomainParameters Parameters => m_parameters;

        public DerObjectIdentifier PublicKeyParamSet => (m_parameters as ECNamedDomainParameters)?.Name;

        public override bool Equals(object obj) => obj is ECKeyParameters other && Equals(other);

        // TODO[api] Should be virtual
        protected bool Equals(ECKeyParameters other) =>
            m_parameters.Equals(other.m_parameters) && base.Equals(other);

        public override int GetHashCode() => m_parameters.GetHashCode() ^ base.GetHashCode();

        internal ECKeyGenerationParameters CreateKeyGenerationParameters(SecureRandom random) =>
            new ECKeyGenerationParameters(m_parameters, random);

        internal static string VerifyAlgorithmName(string algorithm)
        {
            if (!Algorithms.TryGetValue(algorithm, out var upper))
                throw new ArgumentException("unrecognised algorithm: " + algorithm, nameof(algorithm));

            return upper;
        }
    }
}
