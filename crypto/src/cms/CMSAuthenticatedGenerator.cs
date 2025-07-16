using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cms
{
    public class CmsAuthenticatedGenerator
        : CmsEnvelopedGenerator
    {
        public CmsAuthenticatedGenerator()
        {
        }

        /// <summary>Constructor allowing specific source of randomness</summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        public CmsAuthenticatedGenerator(SecureRandom random)
            : base(random)
        {
        }
    }
}
