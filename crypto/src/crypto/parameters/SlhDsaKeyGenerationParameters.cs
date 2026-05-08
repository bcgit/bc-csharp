using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Key generation parameters for SLH-DSA (FIPS 205). Carries the <see cref="SecureRandom"/> used to
    /// draw the seed material together with the chosen <see cref="SlhDsaParameters"/> selector. Strength
    /// is implied by the parameter set, so the base <c>strength</c> field is left at zero.
    /// </summary>
    public sealed class SlhDsaKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly SlhDsaParameters m_parameters;

        /// <summary>Construct using <paramref name="parameters"/> directly.</summary>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> is <c>null</c>.</exception>
        public SlhDsaKeyGenerationParameters(SecureRandom random, SlhDsaParameters parameters)
            : base(random, 0)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>Construct by looking up the parameter set for <paramref name="parametersOid"/>.</summary>
        /// <exception cref="ArgumentNullException">If <paramref name="parametersOid"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="parametersOid"/> is not a recognised
        /// SLH-DSA parameter OID.</exception>
        public SlhDsaKeyGenerationParameters(SecureRandom random, DerObjectIdentifier parametersOid)
            : base(random, 0)
        {
            if (parametersOid == null)
                throw new ArgumentNullException(nameof(parametersOid));
            if (!SlhDsaParameters.ByOid.TryGetValue(parametersOid, out m_parameters))
                throw new ArgumentException("unrecognised SLH-DSA parameters OID", nameof(parametersOid));
        }

        /// <summary>The SLH-DSA parameter set the generated key pair will be bound to.</summary>
        public SlhDsaParameters Parameters => m_parameters;
    }
}
