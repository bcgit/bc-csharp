using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Tls
{
    public class DefaultTlsHeartbeat
        : TlsHeartbeat
    {
        private readonly int idleMillis, timeoutMillis;

        private uint counter = 0U;

        /// <summary>Create a new <see cref="DefaultTlsHeartbeat"/>.</summary>
        /// <param name="idleMillis">The idle millis.</param>
        /// <param name="timeoutMillis">The timeout millis.</param>
        public DefaultTlsHeartbeat(int idleMillis, int timeoutMillis)
        {
            if (idleMillis <= 0)
                throw new ArgumentException("must be > 0", "idleMillis");
            if (timeoutMillis <= 0)
                throw new ArgumentException("must be > 0", "timeoutMillis");

            this.idleMillis = idleMillis;
            this.timeoutMillis = timeoutMillis;
        }

        /// <inheritdoc/>
        public virtual byte[] GeneratePayload()
        {
            lock (this)
            {
                // NOTE: The counter naturally wraps back to 0
                return Pack.UInt32_To_BE(++counter);
            }
        }

        /// <inheritdoc/>
        public virtual int IdleMillis
        {
            get { return idleMillis; }
        }

        /// <inheritdoc/>
        public virtual int TimeoutMillis
        {
            get { return timeoutMillis; }
        }
    }
}
