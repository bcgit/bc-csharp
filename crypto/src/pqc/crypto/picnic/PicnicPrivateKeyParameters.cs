using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Picnic
{
    public sealed class PicnicPrivateKeyParameters
        : PicnicKeyParameters
    {
        private readonly byte[] m_privateKey;

        /// <summary>Create a new <see cref="PicnicPrivateKeyParameters"/>.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <param name="skEncoded">The sk encoded.</param>
        public PicnicPrivateKeyParameters(PicnicParameters parameters, byte[] skEncoded)
            : base(true, parameters)
        {
            m_privateKey = Arrays.Clone(skEncoded);
        }

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded()
        {
            return Arrays.Clone(m_privateKey);
        }
    }
}
