using System;
using System.Collections.Generic;
#if !PORTABLE
using System.Runtime.Serialization;
#endif
using System.Text;

namespace Org.BouncyCastle.Crmf
{
    public class CrmfException : Exception
    {
        public CrmfException()
        {
        }

        public CrmfException(string message) : base(message)
        {
        }

        public CrmfException(string message, Exception innerException) : base(message, innerException)
        {
        }
#if !PORTABLE
        protected CrmfException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
#endif
    }
}
