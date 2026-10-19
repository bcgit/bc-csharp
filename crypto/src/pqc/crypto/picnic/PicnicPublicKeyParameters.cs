using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    public sealed class PicnicPublicKeyParameters
        : PicnicKeyParameters
    {
        private readonly byte[] m_publicKey;

        /// <summary>Create a new <see cref="PicnicPublicKeyParameters"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="pkEncoded">The pk encoded.</param>
        public PicnicPublicKeyParameters(PicnicParameters parameters, byte[] pkEncoded)
            : base(false, parameters)
        {
            m_publicKey = Arrays.Clone(pkEncoded);
        }

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded()
        {
            return Arrays.Clone(m_publicKey);
        }
    }
}
