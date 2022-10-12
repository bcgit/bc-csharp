
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public class SaberKeyParameters
        : AsymmetricKeyParameter
    {
        private SaberParameters parameters;

        public SaberKeyParameters(
            bool isPrivate,
            SaberParameters parameters)
            : base(isPrivate)
        {
            this.parameters = parameters;
        }

        public SaberParameters GetParameters()
        {
            return parameters;
        }
    }
}