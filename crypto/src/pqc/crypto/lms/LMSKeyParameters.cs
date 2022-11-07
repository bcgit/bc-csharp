using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public abstract class LmsKeyParameters
        : AsymmetricKeyParameter, IEncodable
    {
        internal LmsKeyParameters(bool isPrivateKey)
            : base(isPrivateKey)
        {
        }

        public abstract byte[] GetEncoded();
    }
}
