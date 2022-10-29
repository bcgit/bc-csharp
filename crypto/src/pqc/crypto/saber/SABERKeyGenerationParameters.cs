using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Saber
{
    public sealed class SaberKeyGenerationParameters
        : KeyGenerationParameters
    {
        private SaberParameters parameters;

        public SaberKeyGenerationParameters(SecureRandom random, SaberParameters saberParameters)
            : base(random, 256)
        {
            this.parameters = saberParameters;
        }

        public SaberParameters Parameters => parameters;
    }
}
