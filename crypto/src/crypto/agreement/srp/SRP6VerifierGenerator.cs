using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement.Srp
{
    /// <summary>Generates new SRP verifier for user.</summary>
    public class Srp6VerifierGenerator
    {
        protected BigInteger N;
        protected BigInteger g;
        protected IDigest digest;
        protected SecureRandom random;

        public Srp6VerifierGenerator()
        {
        }

        /// <summary>Initialises generator to create new verifiers.</summary>
        /// <param name="N">The safe prime to use (see DHParametersGenerator).</param>
        /// <param name="g">The group parameter to use (see DHParametersGenerator).</param>
        /// <param name="digest">The digest to use. The same digest type will need to be used later for the actual
        /// authentication attempt. Also note that the final session key size is dependent on the chosen digest.</param>
        public virtual void Init(BigInteger N, BigInteger g, IDigest digest) => Init(N, g, digest, random: null);

        /// <summary>Initialises generator to create new verifiers.</summary>
        /// <param name="N">The safe prime to use (see DHParametersGenerator).</param>
        /// <param name="g">The group parameter to use (see DHParametersGenerator).</param>
        /// <param name="digest">The digest to use. The same digest type will need to be used later for the actual
        /// authentication attempt. Also note that the final session key size is dependent on the chosen digest.</param>
        /// <param name="random">
        /// The source used to randomise the private exponent before it is raised, may be null to take the default from
        /// <see cref="CryptoServicesRegistrar.GetSecureRandom(SecureRandom)"/>.
        /// </param>
        public virtual void Init(BigInteger N, BigInteger g, IDigest digest, SecureRandom random)
        {
            this.N = N;
            this.g = g;
            this.digest = digest;
            this.random = CryptoServicesRegistrar.GetSecureRandom(random);
        }

        public virtual void Init(Srp6GroupParameters group, IDigest digest) => Init(group, digest, random: null);

        public virtual void Init(Srp6GroupParameters group, IDigest digest, SecureRandom random) =>
            Init(group.N, group.G, digest, random);

        /// <summary>Creates a new SRP verifier.</summary>
        /// <param name="salt">The salt to use, generally should be large and random.</param>
        /// <param name="identity">The user's identifying information (eg. username).</param>
        /// <param name="password">The user's password.</param>
        /// <returns>A new verifier for use in future SRP authentication.</returns>
        public virtual BigInteger GenerateVerifier(byte[] salt, byte[] identity, byte[] password)
        {
            BigInteger x = Srp6Utilities.CalculateX(digest, N, salt, identity, password);

            // x is derived from the password, making it the longest lived secret in the protocol, so the
            // exponent is randomised before the variable-time BigInteger.modPow sees it. Raising g to
            // the power N-1 gives 1 by Fermat's little theorem, so the verifier is unchanged.
            BigInteger blindedX = BigIntegers.CreateBlindedExponent(x, N.Subtract(BigIntegers.One), random);

            return g.ModPow(blindedX, N);
        }
    }
}
