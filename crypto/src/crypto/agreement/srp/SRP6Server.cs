using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement.Srp
{
    /// <summary>Implements the server side SRP-6a protocol.</summary>
    /// <remarks>
    /// Note that this class is stateful, and therefore NOT threadsafe. This implementation of SRP is based on the
    /// optimized message sequence put forth by Thomas Wu in the paper "SRP-6: Improvements and Refinements to the
    /// Secure Remote Password Protocol, 2002".
    /// </remarks>
    public class Srp6Server
    {
        protected BigInteger N;
        protected BigInteger g;
        protected BigInteger v;

        protected SecureRandom random;
        protected IDigest digest;

        protected BigInteger A;

        protected BigInteger privB;
        protected BigInteger pubB;

        protected BigInteger u;
        protected BigInteger S;
        protected BigInteger M1;
        protected BigInteger M2;
        protected BigInteger Key;

        public Srp6Server()
        {
        }

        /// <summary>Initialises the server to accept a new client authentication attempt.</summary>
        /// <param name="N">The safe prime associated with the client's verifier.</param>
        /// <param name="g">The group parameter associated with the client's verifier.</param>
        /// <param name="v">The client's verifier.</param>
        /// <param name="digest">The digest algorithm associated with the client's verifier.</param>
        /// <param name="random">For key generation.</param>
        public virtual void Init(BigInteger N, BigInteger g, BigInteger v, IDigest digest, SecureRandom random)
        {
            this.N = N;
            this.g = g;
            this.v = v;

            this.random = CryptoServicesRegistrar.GetSecureRandom(random);
            this.digest = digest;
        }

        public virtual void Init(Srp6GroupParameters group, BigInteger v, IDigest digest, SecureRandom random)
        {
            Init(group.N, group.G, v, digest, random);
        }

        /// <summary>Generates the server's credentials that are to be sent to the client.</summary>
        /// <returns>The server's public value to the client.</returns>
        public virtual BigInteger GenerateServerCredentials()
        {
            BigInteger k = Srp6Utilities.CalculateK(digest, N, g);
            this.privB = SelectPrivateValue();
            this.pubB = k.Multiply(v).Mod(N).Add(g.ModPow(BlindExponent(privB), N)).Mod(N);

            return pubB;
        }

        /// <summary>Processes the client's credentials. If valid the shared secret is generated and returned.</summary>
        /// <param name="clientA">The client's credentials.</param>
        /// <returns>A shared secret BigInteger.</returns>
        /// <exception cref="CryptoException">If client's credentials are invalid.</exception>
        public virtual BigInteger CalculateSecret(BigInteger clientA)
        {
            this.A = Srp6Utilities.ValidatePublicValue(N, clientA);
            this.u = Srp6Utilities.CalculateU(digest, N, A, pubB);
            this.S = CalculateS();

            return S;
        }

        protected virtual BigInteger SelectPrivateValue()
        {
            return Srp6Utilities.GeneratePrivateValue(digest, N, g, random);
        }

        private BigInteger CalculateS()
        {
            // TODO Consider base blinding to protect 'v'
            return v.ModPow(u, N).ModMultiply(A, N).ModPow(BlindExponent(privB), N);
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

        /// <summary>Authenticates the received client evidence message M1 and saves it only if correct.</summary>
        /// <remarks>To be called after calculating the secret S.</remarks>
        /// <param name="clientM1">The client side generated evidence message.</param>
        /// <returns>A boolean indicating if the client message M1 was the expected one.</returns>
        /// <exception cref="CryptoException"/>
        public virtual bool VerifyClientEvidenceMessage(BigInteger clientM1)
        {
            // Verify pre-requirements
            if (this.A == null || this.pubB == null || this.S == null)
            {
                throw new CryptoException("Impossible to compute and verify M1: " +
                        "some data are missing from the previous operations (A,B,S)");
            }

            // Compute the own client evidence message 'M1'
            BigInteger computedM1 = Srp6Utilities.CalculateM1(digest, N, A, pubB, S);
            if (computedM1.Equals(clientM1))
            {
                this.M1 = clientM1;
                return true;
            }
            return false;
        }

        /// <summary>Computes the server evidence message M2 using the previously verified values.</summary>
        /// <remarks>To be called after successfully verifying the client evidence message M1.</remarks>
        /// <returns>M2: the server side generated evidence message.</returns>
        /// <exception cref="CryptoException"/>
        public virtual BigInteger CalculateServerEvidenceMessage()
        {
            // Verify pre-requirements
            if (this.A == null || this.M1 == null || this.S == null)
            {
                throw new CryptoException("Impossible to compute M2: " +
                        "some data are missing from the previous operations (A,M1,S)");
            }

            // Compute the server evidence message 'M2'
            this.M2 = Srp6Utilities.CalculateM2(digest, N, A, M1, S);
            return M2;
        }

        /// <summary>
        /// Computes the final session key as a result of the SRP successful mutual authentication.
        /// </summary>
        /// <remarks>To be called after calculating the server evidence message M2.</remarks>
        /// <returns>Key: the mutual authenticated symmetric session key.</returns>
        /// <exception cref="CryptoException"/>
        public virtual BigInteger CalculateSessionKey()
        {
            // Verify pre-requirements
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
