using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    /// <summary>The parameters for generating Picnic keys.</summary>
    public class PicnicKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly PicnicParameters m_parameters;

        /// <summary>Create a new <see cref="PicnicKeyGenerationParameters"/>.</summary>
        /// <param name="random">The source of randomness.</param>
        /// <param name="parameters">The parameters.</param>
        public PicnicKeyGenerationParameters(SecureRandom random, PicnicParameters parameters)
            : base(random, 255)
        {
            m_parameters = parameters;
        }

        /// <summary>Gets the parameters.</summary>
        public PicnicParameters Parameters => m_parameters;
    }
}
