using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for generating Diffie-Hellman key pairs.</summary>
    public class DHKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly DHParameters parameters;

        /// <summary>Create a new <see cref="DHKeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="parameters">The parameters.</param>
        public DHKeyGenerationParameters(
            SecureRandom random,
            DHParameters parameters)
            : base(random, GetStrength(parameters))
        {
            this.parameters = parameters;
        }

        public DHParameters Parameters
        {
            get { return parameters; }
        }

        internal static int GetStrength(
            DHParameters parameters)
        {
            return parameters.L != 0 ? parameters.L : parameters.P.BitLength;
        }
    }
}
