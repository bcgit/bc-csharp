using System;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>Implementation of the ARIA key wrap with padding algorithm (RFC 5649).</summary>
    public class AriaWrapPadEngine
        : Rfc5649WrapEngine
    {
        /// <summary>Create a new <see cref="AriaWrapPadEngine"/>.</summary>
        public AriaWrapPadEngine()
            : base(new AriaEngine())
        {
        }
    }
}
