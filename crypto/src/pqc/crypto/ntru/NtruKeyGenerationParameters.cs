using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru
{
    /// <summary>Key generation parameters for NTRU, binding a randomness source to an NTRU parameter set.</summary>
    public class NtruKeyGenerationParameters : KeyGenerationParameters
    {
        internal NtruParameters NtruParameters { get; }

        /// <summary>Creates key generation parameters for the given NTRU parameter set.</summary>
        /// <param name="random">The randomness source for key generation.</param>
        /// <param name="ntruParameters">The NTRU parameter set to generate keys for.</param>
        // We won't be using strength as the key length differs between public & private key
        public NtruKeyGenerationParameters(SecureRandom random, NtruParameters ntruParameters) : base(random, 1)
        {
            NtruParameters = ntruParameters;
        }

        /// <summary>The NTRU parameter set keys will be generated for.</summary>
        public NtruParameters GetParameters()
        {
            return NtruParameters;
        }
    }
}