using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    public interface TlsPeer
    {
        /// <summary>
        /// draft-mathewson-no-gmtunixtime-00 2. "If existing users of a TLS implementation may rely on
        /// gmt_unix_time containing the current time, we recommend that implementors MAY provide the
        /// ability to set gmt_unix_time as an option only, off by default."
        /// </summary>
        /// <returns>
        /// <code>true</code> if the current time should be used in the gmt_unix_time field of
        /// Random, or <code>false</code> if gmt_unix_time should contain a cryptographically
        /// random value.
        /// </returns>
        bool ShouldUseGmtUnixTime();
    }
}
