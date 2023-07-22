using System;

namespace Org.BouncyCastle.Crypto.Engines
{
    public class AriaWrapPadEngine
        : Rfc5649WrapEngine
    {
        public AriaWrapPadEngine()
            : base(new AriaEngine())
        {
        }
    }
}
