using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Tls
{
	public class TlsClientContextImpl : AbstractTlsContext, TlsClientContext
	{	
		public TlsClientContextImpl(SecureRandom secureRandom, SecurityParameters securityParameters)
            : base(secureRandom ,  securityParameters)
		{
			
		}		

        public override bool IsServer
        {
            get { return false; }
        }
    }
}
