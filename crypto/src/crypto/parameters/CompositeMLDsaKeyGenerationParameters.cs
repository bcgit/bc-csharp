using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Key generation parameters for Composite ML-DSA. Carries the <see cref="SecureRandom"/> used by both
    /// component generators together with the chosen <see cref="CompositeMLDsaParameters"/> combination.
    /// Strength is implied by the combination, so the base <c>strength</c> field is left at zero.
    /// </summary>
    public sealed class CompositeMLDsaKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly CompositeMLDsaParameters m_parameters;

        /// <summary>Construct using <paramref name="parameters"/> directly.</summary>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> is <c>null</c>.</exception>
        public CompositeMLDsaKeyGenerationParameters(SecureRandom random, CompositeMLDsaParameters parameters)
            : base(random, 0)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>Construct by looking up the combination for <paramref name="parametersOid"/>.</summary>
        /// <exception cref="ArgumentNullException">If <paramref name="parametersOid"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="parametersOid"/> is not a recognised
        /// Composite ML-DSA OID.</exception>
        public CompositeMLDsaKeyGenerationParameters(SecureRandom random, DerObjectIdentifier parametersOid)
            : base(random, 0)
        {
            if (parametersOid == null)
                throw new ArgumentNullException(nameof(parametersOid));
            if (!CompositeMLDsaParameters.ByOid.TryGetValue(parametersOid, out m_parameters))
                throw new ArgumentException("unrecognised Composite ML-DSA parameters OID", nameof(parametersOid));
        }

        /// <summary>The combination the generated key pair will be bound to.</summary>
        public CompositeMLDsaParameters Parameters => m_parameters;
    }
}
