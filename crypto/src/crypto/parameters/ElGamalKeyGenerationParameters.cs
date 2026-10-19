using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for generating ElGamal key pairs.</summary>
    public class ElGamalKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly ElGamalParameters parameters;

        /// <summary>Create a new <see cref="ElGamalKeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="parameters">The parameters.</param>
        public ElGamalKeyGenerationParameters(
            SecureRandom random,
            ElGamalParameters parameters)
            : base(random, GetStrength(parameters))
        {
            this.parameters = parameters;
        }

        public ElGamalParameters Parameters
        {
            get { return parameters; }
        }

        internal static int GetStrength(
            ElGamalParameters parameters)
        {
            return parameters.L != 0 ? parameters.L : parameters.P.BitLength;
        }
    }
}
