using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>The SRP login parameters of a user, as returned by a server's identity manager.</summary>
    public class TlsSrpLoginParameters
    {
        protected byte[] m_identity;
        /// <summary>The srp config.</summary>
        protected TlsSrpConfig m_srpConfig;
        protected BigInteger m_verifier;
        protected byte[] m_salt;

        /// <summary>Create a new <see cref="TlsSrpLoginParameters"/>.</summary>
        /// <param name="identity">The identity.</param>
        /// <param name="srpConfig">The srp config.</param>
        /// <param name="verifier">The verifier.</param>
        /// <param name="salt">The salt.</param>
        public TlsSrpLoginParameters(byte[] identity, TlsSrpConfig srpConfig, BigInteger verifier, byte[] salt)
        {
            this.m_identity = Arrays.Clone(identity);
            this.m_srpConfig = srpConfig;
            this.m_verifier = verifier;
            this.m_salt = Arrays.Clone(salt);
        }

        /// <summary>Gets the config.</summary>
        public virtual TlsSrpConfig Config
        {
            get { return m_srpConfig; }
        }

        /// <summary>Gets the identity.</summary>
        public virtual byte[] Identity
        {
            get { return m_identity; }
        }

        /// <summary>Gets the salt.</summary>
        public virtual byte[] Salt
        {
            get { return m_salt; }
        }

        /// <summary>Gets the verifier.</summary>
        public virtual BigInteger Verifier
        {
            get { return m_verifier; }
        }
    }
}
