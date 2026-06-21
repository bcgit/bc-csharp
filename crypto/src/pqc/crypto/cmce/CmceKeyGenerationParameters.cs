using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Cmce
{
    /// <summary>
    /// Key generation parameters for Classic McEliece, binding a randomness source to a parameter set.
    /// </summary>
    public sealed class CmceKeyGenerationParameters
        : KeyGenerationParameters
    {
        private CmceParameters parameters;

        /// <summary>Creates key generation parameters for the given Classic McEliece parameter set.</summary>
        /// <param name="random">The randomness source for key generation.</param>
        /// <param name="CmceParams">The Classic McEliece parameter set to generate keys for.</param>
        public CmceKeyGenerationParameters(SecureRandom random, CmceParameters CmceParams)
            : base(random, 256)
        {
            this.parameters = CmceParams;
        }

        /// <summary>The Classic McEliece parameter set keys will be generated for.</summary>
        public CmceParameters Parameters => parameters;
    }
}
