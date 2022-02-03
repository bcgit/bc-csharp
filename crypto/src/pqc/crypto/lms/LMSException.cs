using System;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public class LMSException
        : Exception
    {
        public LMSException()
        {
        }

        public LMSException(string message)
            : base(message)
        {
        }

        public LMSException(string message, Exception cause)
            : base(message, cause)
        {
        }
    }
}