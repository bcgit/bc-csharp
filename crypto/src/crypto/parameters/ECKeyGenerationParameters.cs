using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for generating elliptic curve key pairs.</summary>
    public class ECKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly ECDomainParameters m_domainParameters;

        /// <summary>Create a new <see cref="ECKeyGenerationParameters"/>.</summary>
        /// <param name="domainParameters">The domain parameters.</param>
        /// <param name="random">The source of randomness.</param>
        public ECKeyGenerationParameters(ECDomainParameters domainParameters, SecureRandom random)
            : base(random, domainParameters.N.BitLength)
        {
            m_domainParameters = domainParameters;
        }

        /// <summary>Create a new <see cref="ECKeyGenerationParameters"/>.</summary>
        /// <param name="publicKeyParamSet">The public key param set.</param>
        /// <param name="random">The source of randomness.</param>
        public ECKeyGenerationParameters(DerObjectIdentifier publicKeyParamSet, SecureRandom random)
            : this(ECNamedDomainParameters.LookupOid(oid: publicKeyParamSet), random)
        {
        }

        /// <summary>Gets the domain parameters.</summary>
        public ECDomainParameters DomainParameters => m_domainParameters;

        /// <summary>Gets the public key param set.</summary>
        public DerObjectIdentifier PublicKeyParamSet => (m_domainParameters as ECNamedDomainParameters)?.Name;
    }
}
