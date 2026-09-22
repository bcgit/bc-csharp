using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement.Srp
{
    /// <summary>Implements the client side SRP-6a protocol.</summary>
    /// <remarks>
    /// Note that this class is stateful, and therefore NOT threadsafe. This implementation of SRP is based on the
    /// optimized message sequence put forth by Thomas Wu in the paper "SRP-6: Improvements and Refinements to the
    /// Secure Remote Password Protocol, 2002".
    /// </remarks>
    public class Srp6Client
    {
        protected BigInteger N;
        protected BigInteger g;

        protected BigInteger privA;
        protected BigInteger pubA;

        protected BigInteger B;

        protected BigInteger x;
        protected BigInteger u;
        protected BigInteger S;

        protected BigInteger M1;
        protected BigInteger M2;
        protected BigInteger Key;

        protected IDigest digest;
        protected SecureRandom random;

        public Srp6Client()
        {
        }

        /// <summary>Initialises the client to begin new authentication attempt.</summary>
        /// <param name="N">The safe prime associated with the client's verifier.</param>
        /// <param name="g">The group parameter associated with the client's verifier.</param>
        /// <param name="digest">The digest algorithm associated with the client's verifier.</param>
        /// <param name="random">For key generation.</param>
        public virtual void Init(BigInteger N, BigInteger g, IDigest digest, SecureRandom random)
        {
            this.N = N;
            this.g = g;
            this.digest = digest;
            this.random = CryptoServicesRegistrar.GetSecureRandom(random);
        }

        public virtual void Init(Srp6GroupParameters group, IDigest digest, SecureRandom random)
        {
            Init(group.N, group.G, digest, random);
        }

        /// <summary>Generates client's credentials given the client's salt, identity and password.</summary>
        /// <param name="salt">The salt used in the client's verifier.</param>
        /// <param name="identity">The user's identity (eg. username).</param>
        /// <param name="password">The user's password.</param>
        /// <returns>Client's public value to send to server.</returns>
        public virtual BigInteger GenerateClientCredentials(byte[] salt, byte[] identity, byte[] password)
        {
            this.x = Srp6Utilities.CalculateX(digest, N, salt, identity, password);
            this.privA = SelectPrivateValue();
            this.pubA = g.ModPow(BlindExponent(privA), N);

            return pubA;
        }

        /// <summary>Generates client's verification message given the server's credentials.</summary>
        /// <param name="serverB">The server's credentials.</param>
        /// <returns>Client's verification message for the server.</returns>
        /// <exception cref="CryptoException">If server's credentials are invalid.</exception>
        public virtual BigInteger CalculateSecret(BigInteger serverB)
        {
            this.B = Srp6Utilities.ValidatePublicValue(N, serverB);
            this.u = Srp6Utilities.CalculateU(digest, N, pubA, B);
            this.S = CalculateS();

            return S;
        }

        protected virtual BigInteger SelectPrivateValue()
        {
            return Srp6Utilities.GeneratePrivateValue(digest, N, g, random);
        }

        private BigInteger CalculateS()
        {
            BigInteger k = Srp6Utilities.CalculateK(digest, N, g);
            BigInteger exp = u.Multiply(x).Add(privA);
            BigInteger tmp = g.ModPow(BlindExponent(x), N).Multiply(k).Mod(N);
            return B.Subtract(tmp).Mod(N).ModPow(BlindExponent(exp), N);
        }

        /// <summary>
        /// Add a random multiple of N-1 to a private exponent, so that the variable-time
        /// <see cref="BigInteger.ModPow(BigInteger, BigInteger)"/> applied to it sees a different exponent.
        /// </summary>
        /// <remarks>
        /// Raising any value coprime to the prime N to the power N-1 gives 1 by Fermat's little theorem, so the result
        /// is unchanged. The multiple is of N-1 rather than of the order of g because the base blinded in
        /// <see cref="CalculateS"/> carries a client-supplied value that need not lie in the subgroup g generates, and
        /// for a safe prime an odd multiple of that order would give the wrong answer for the values that do not.
        /// </remarks>
        private BigInteger BlindExponent(BigInteger e)
        {
            return BigIntegers.CreateBlindedExponent(e, N.Subtract(BigIntegers.One), random);
        }

        /// <summary>Computes the client evidence message M1 using the previously received values.</summary>
        /// <remarks>To be called after calculating the secret S.</remarks>
        /// <returns>M1: the client side generated evidence message.</returns>
        /// <exception cref="CryptoException"/>
        public virtual BigInteger CalculateClientEvidenceMessage()
        {
            // Verify pre-requirements
            if (this.pubA == null || this.B == null || this.S == null)
            {
                throw new CryptoException("Impossible to compute M1: " +
                        "some data are missing from the previous operations (A,B,S)");
            }
            // compute the client evidence message 'M1'
            this.M1 = Srp6Utilities.CalculateM1(digest, N, pubA, B, S);
            return M1;
        }

        /// <summary>Authenticates the server evidence message M2 received and saves it only if correct.</summary>
        /// <param name="serverM2">The server side generated evidence message.</param>
        /// <returns>A boolean indicating if the server message M2 was the expected one.</returns>
        /// <exception cref="CryptoException"/>
        public virtual bool VerifyServerEvidenceMessage(BigInteger serverM2)
        {
            // Verify pre-requirements
            if (this.pubA == null || this.M1 == null || this.S == null)
            {
                throw new CryptoException("Impossible to compute and verify M2: " +
                        "some data are missing from the previous operations (A,M1,S)");
            }

            // Compute the own server evidence message 'M2'
            BigInteger computedM2 = Srp6Utilities.CalculateM2(digest, N, pubA, M1, S);
            if (computedM2.Equals(serverM2))
            {
                this.M2 = serverM2;
                return true;
            }
            return false;
        }

        /// <summary>
        /// Computes the final session key as a result of the SRP successful mutual authentication.
        /// </summary>
        /// <remarks>To be called after verifying the server evidence message M2.</remarks>
        /// <returns>Key: the mutually authenticated symmetric session key.</returns>
        /// <exception cref="CryptoException"/>
        public virtual BigInteger CalculateSessionKey()
        {
            // Verify pre-requirements (here we enforce a previous calculation of M1 and M2)
            if (this.S == null || this.M1 == null || this.M2 == null)
            {
                throw new CryptoException("Impossible to compute Key: " +
                        "some data are missing from the previous operations (S,M1,M2)");
            }
            this.Key = Srp6Utilities.CalculateKey(digest, N, S);
            return Key;
        }
    }
}
