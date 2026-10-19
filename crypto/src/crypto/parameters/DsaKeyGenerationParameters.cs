using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for generating DSA key pairs.</summary>
    public class DsaKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly DsaParameters parameters;

        /// <summary>Create a new <see cref="DsaKeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="parameters">The parameters.</param>
        public DsaKeyGenerationParameters(
            SecureRandom random,
            DsaParameters parameters)
            : base(random, parameters.P.BitLength - 1)
        {
            this.parameters = parameters;
        }

        public DsaParameters Parameters
        {
            get { return parameters; }
        }
    }

}
