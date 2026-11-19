using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// Common base for XMSS public and private key parameters (RFC 8391); carries the <see cref="XmssParameters"/>
    /// the key was generated for.
    /// </summary>
    public abstract class XmssKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly XmssParameters m_parameters;

        internal XmssKeyParameters(bool isPrivateKey, XmssParameters parameters)
            : base(isPrivateKey)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        /// <summary>The parameter set this key is bound to.</summary>
        public XmssParameters Parameters => m_parameters;

        /// <summary>The name of the digest the key's tree is built with.</summary>
        public string TreeDigest => m_parameters.TreeDigest;
    }
}
