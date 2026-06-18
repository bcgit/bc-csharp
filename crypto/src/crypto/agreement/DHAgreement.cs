using System;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
    /// <summary>
    /// A Diffie-Hellman key exchange engine.
    /// </summary>
    /// <remarks>
    /// This uses MTI/A0 key agreement in order to make the key agreement secure against passive attacks. If you're
    /// doing Diffie-Hellman and both parties have long term public keys you should look at using this. For further
    /// information have a look at RFC 2631.
    /// <para>
    /// It's possible to extend this to more than two parties as well, for the moment that is left as an exercise for
    /// the reader.
    /// </para>
    /// </remarks>
    // TODO[api] sealed
    public class DHAgreement
    {
        private DHPrivateKeyParameters m_key;
        private DHParameters m_dhParams;
        private SecureRandom m_random;
        private BigInteger m_privateValue;

        public void Init(ICipherParameters parameters)
        {
            var kParam = ParameterUtilities.GetRandom(parameters, out var providedRandom);

            if (!(kParam is DHPrivateKeyParameters dhPrivateKeyParameters))
                throw new ArgumentException($"{nameof(DHAgreement)} expects {nameof(DHPrivateKeyParameters)}");

            m_key = dhPrivateKeyParameters;
            m_dhParams = dhPrivateKeyParameters.Parameters;
            m_random = CryptoServicesRegistrar.GetSecureRandom(providedRandom);
            m_privateValue = null;
        }

        /// <summary>Calculate our initial message.</summary>
        public BigInteger CalculateMessage()
        {
            DHKeyPairGenerator dhGen = new DHKeyPairGenerator();
            dhGen.Init(new DHKeyGenerationParameters(m_random, m_dhParams));
            AsymmetricCipherKeyPair dhPair = dhGen.GenerateKeyPair();

            m_privateValue = ((DHPrivateKeyParameters)dhPair.Private).X;

            return ((DHPublicKeyParameters)dhPair.Public).Y;
        }

        /// <summary>
        /// Given a message from a given party and the corresponding public key calculate the next message in the
        /// agreement sequence. In this case this will represent the shared secret.
        /// </summary>
        public BigInteger CalculateAgreement(DHPublicKeyParameters pub, BigInteger message)
        {
            if (pub == null)
                throw new ArgumentNullException(nameof(pub));
            if (message == null)
                throw new ArgumentNullException(nameof(message));

            if (!pub.Parameters.Equals(m_dhParams))
                throw new ArgumentException("Diffie-Hellman public key has wrong parameters.");

            BigInteger p = m_dhParams.P;

            // Both peer-supplied values are raised to our (potentially static) private key, so both must
            // satisfy the DH public-value range/subgroup checks; otherwise a peer can submit a small-order
            // or out-of-range element to mount a small-subgroup confinement attack and, when our private
            // key is reused, recover it via CRT. The 'message' is a raw BigInteger, so validate it by
            // construction. A normally-constructed DHPublicKeyParameters already validated its Y; but Y is
            // virtual and a subclass can override it to return an unvalidated value, so re-validate unless
            // pub is exactly the base type.
            BigInteger peerMessage = new DHPublicKeyParameters(message, m_dhParams).Y;

            BigInteger peerY = pub.GetType() == typeof(DHPublicKeyParameters)
                ? pub.Y
                : new DHPublicKeyParameters(pub.Y, m_dhParams).Y;

            BigInteger result = peerY.ModPow(m_privateValue, p);
            if (result.Equals(BigInteger.One))
                throw new InvalidOperationException("Shared key can't be 1");

            return peerMessage.ModPow(m_key.X, p).Multiply(result).Mod(p);
        }
    }
}
