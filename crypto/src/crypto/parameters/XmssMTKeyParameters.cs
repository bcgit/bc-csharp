using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Common base for XMSS^MT public and private key parameters (RFC 8391); carries the
    /// <see cref="XmssMTParameters"/> the key was generated for.
    /// </summary>
    public abstract class XmssMTKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly XmssMTParameters m_parameters;

        internal XmssMTKeyParameters(bool isPrivateKey, XmssMTParameters parameters)
            : base(isPrivateKey)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>The parameter set this key is bound to.</summary>
        public XmssMTParameters Parameters => m_parameters;

        /// <summary>The name of the digest the key's trees are built with.</summary>
        public string TreeDigest => m_parameters.TreeDigest;
    }
}
