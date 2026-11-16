using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Processor interface for an SRP identity.</summary>
    public interface TlsSrpIdentity
    {
        /// <summary>Return the srp identity.</summary>
        byte[] GetSrpIdentity();

        /// <summary>Return the srp password.</summary>
        byte[] GetSrpPassword();
    }
}
