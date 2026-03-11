using System;
using System.IO;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Security
{
    [Obsolete("Use Org.BouncyCastle.OpenSsl.EncryptionException instead")]
    [Serializable]
    public class EncryptionException
        : IOException
    {
        public EncryptionException()
            : base()
        {
        }

        public EncryptionException(string message)
            : base(message)
        {
        }

        public EncryptionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected EncryptionException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
