using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text;

namespace Org.BouncyCastle.Asn1.Crmf
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

        protected CrmfException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
