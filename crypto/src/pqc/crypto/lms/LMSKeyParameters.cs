using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>Base class for LMS keys.</summary>
    public abstract class LmsKeyParameters
        : AsymmetricKeyParameter, IEncodable
    {
        internal LmsKeyParameters(bool isPrivateKey)
            : base(isPrivateKey)
        {
        }

        /// <inheritdoc/>
        public abstract byte[] GetEncoded();
    }
}
