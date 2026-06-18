using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Agreement
{
    /// <summary>
    /// A Diffie-Hellman key agreement class.
    /// </summary>
    /// <remarks>
    /// This is only the basic algorithm, it doesn't take advantage of long term public keys if they are available. See
    /// the DHAgreement class for a "better" implementation.
    /// </remarks>
    // TODO[api] sealed
    public class DHBasicAgreement
        : IBasicAgreement
    {
        private DHPrivateKeyParameters m_key;
        private DHParameters m_dhParams;

        public virtual void Init(ICipherParameters parameters)
        {
            var kParam = ParameterUtilities.IgnoreRandom(parameters);

            if (!(kParam is DHPrivateKeyParameters dhPrivateKeyParameters))
                throw new ArgumentException($"{nameof(DHBasicAgreement)} expects {nameof(DHPrivateKeyParameters)}");

            m_key = dhPrivateKeyParameters;
            m_dhParams = m_key.Parameters;
        }

        public virtual int GetFieldSize() => (m_key.Parameters.P.BitLength + 7) / 8;

        /// <summary>
        /// Given a short term public key from a given party calculate the next message in the agreement sequence.
        /// </summary>
        public virtual BigInteger CalculateAgreement(ICipherParameters pubKey)
        {
            if (m_key == null)
                throw new InvalidOperationException("Agreement algorithm not initialised");

            DHPublicKeyParameters pub = (DHPublicKeyParameters)pubKey;

            if (!pub.Parameters.Equals(m_dhParams))
                throw new ArgumentException("Diffie-Hellman public key has wrong parameters.");

            BigInteger p = m_dhParams.P;

            BigInteger peerY = pub.Y;
            if (peerY == null || peerY.CompareTo(BigInteger.One) <= 0 || peerY.CompareTo(p.Subtract(BigInteger.One)) >= 0)
                throw new ArgumentException("Diffie-Hellman public key is weak");

            BigInteger result = peerY.ModPow(m_key.X, p);
            if (result.Equals(BigInteger.One))
                throw new InvalidOperationException("Shared key can't be 1");

            return result;
        }
    }
}
