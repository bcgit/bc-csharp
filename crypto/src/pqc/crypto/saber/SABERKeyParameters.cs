using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public abstract class SaberKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly SaberParameters parameters;

        public SaberKeyParameters(bool isPrivate, SaberParameters parameters)
            : base(isPrivate)
        {
            this.parameters = parameters;
        }

        public SaberParameters Parameters => parameters;
    }
}
