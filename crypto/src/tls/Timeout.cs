using System;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls
{
    internal class Timeout
    {
        private long m_durationMillis;
        private long m_startMillis;

        internal Timeout(long durationMillis)
            : this(durationMillis, DateTimeUtilities.CurrentUnixMs())
        {
        }

        internal Timeout(long durationMillis, long currentTimeMillis)
        {
            m_durationMillis = System.Math.Max(0, durationMillis);
            m_startMillis = System.Math.Max(0, currentTimeMillis);
        }

        internal long RemainingMillis(long currentTimeMillis)
        {
            lock (this)
            {
                // If clock jumped backwards, reset start time 
                if (m_startMillis > currentTimeMillis)
                {
                    m_startMillis = currentTimeMillis;
                    return m_durationMillis;
                }

                long elapsed = currentTimeMillis - m_startMillis;
                long remaining = m_durationMillis - elapsed;

                // Once timeout reached, lock it in
                if (remaining <= 0)
                    return m_durationMillis = 0L;

                return remaining;
            }
        }

        internal static int ConstrainWaitMillis(int waitMillis, Timeout timeout, long currentTimeMillis)
        {
            if (waitMillis < 0)
                return -1;

            int timeoutMillis = GetWaitMillis(timeout, currentTimeMillis);
            if (timeoutMillis < 0)
                return -1;

            if (waitMillis == 0)
                return timeoutMillis;

            if (timeoutMillis == 0)
                return waitMillis;

            return System.Math.Min(waitMillis, timeoutMillis);
        }

        internal static Timeout ForWaitMillis(int waitMillis, long currentTimeMillis)
        {
            if (waitMillis < 0)
                throw new ArgumentException("cannot be negative", nameof(waitMillis));

            if (waitMillis > 0)
                return new Timeout(waitMillis, currentTimeMillis);

            return null;
        }

        internal static int GetWaitMillis(Timeout timeout, long currentTimeMillis)
        {
            if (null == timeout)
                return 0;

            long remainingMillis = timeout.RemainingMillis(currentTimeMillis);
            if (remainingMillis < 1L)
                return -1;

            if (remainingMillis > int.MaxValue)
                return int.MaxValue;

            return (int)remainingMillis;
        }

        internal static bool HasExpired(Timeout timeout, long currentTimeMillis)
        {
            return null != timeout && timeout.RemainingMillis(currentTimeMillis) < 1L;
        }
    }
}
