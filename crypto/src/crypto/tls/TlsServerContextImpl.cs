using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class TlsServerContextImpl : AbstractTlsContext, TlsServerContext
    {
        public TlsServerContextImpl(SecureRandom secureRandom, SecurityParameters securityParameters)
            : base(secureRandom, securityParameters)
        {

        }

        public override bool IsServer
        {
            get
            {
                return true;
            }
        }
    }
}