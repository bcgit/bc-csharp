using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Key generation parameters for ML-DSA (FIPS 204). Carries the <see cref="SecureRandom"/> used to
    /// draw the seed material together with the chosen <see cref="MLDsaParameters"/> selector. Strength
    /// is implied by the parameter set, so the base <c>strength</c> field is left at zero.
    /// </summary>
    public sealed class MLDsaKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly MLDsaParameters m_parameters;

        /// <summary>Construct using <paramref name="parameters"/> directly.</summary>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> is <c>null</c>.</exception>
        public MLDsaKeyGenerationParameters(SecureRandom random, MLDsaParameters parameters)
            : base(random, 0)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>Construct by looking up the parameter set for <paramref name="parametersOid"/>.</summary>
        /// <exception cref="ArgumentNullException">If <paramref name="parametersOid"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="parametersOid"/> is not a recognised
        /// ML-DSA parameter OID (pure or HashML-DSA).</exception>
        public MLDsaKeyGenerationParameters(SecureRandom random, DerObjectIdentifier parametersOid)
            : base(random, 0)
        {
            if (parametersOid == null)
                throw new ArgumentNullException(nameof(parametersOid));
            if (!MLDsaParameters.ByOid.TryGetValue(parametersOid, out m_parameters))
                throw new ArgumentException("unrecognised ML-DSA parameters OID", nameof(parametersOid));
        }

        /// <summary>The ML-DSA parameter set the generated key pair will be bound to.</summary>
        public MLDsaParameters Parameters => m_parameters;
    }
}
