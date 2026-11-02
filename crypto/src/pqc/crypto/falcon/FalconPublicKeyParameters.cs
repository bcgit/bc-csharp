using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    /// <summary>A Falcon public key.</summary>
    public sealed class FalconPublicKeyParameters
        : FalconKeyParameters
    {
        private readonly byte[] m_publicKey;

        /// <summary>Create a new <see cref="FalconPublicKeyParameters"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="h">The h.</param>
        public FalconPublicKeyParameters(FalconParameters parameters, byte[] h)
            : base(false, parameters)
        {
            m_publicKey = Arrays.CopyBuffer(h);
        }

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded() => Arrays.InternalCopyBuffer(m_publicKey);
    }
}
