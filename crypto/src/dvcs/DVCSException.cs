using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.dvcs
{
    public class DVCSException : Exception
    {
        private const long SerialVersionUID = 389345256020131488L;

        private Exception Cause { get; set; } 

        public DVCSException(String message) : base(message)
        {
            
        }

        public DVCSException(String message, Exception cause) :base(message)
        {
           
            this.Cause = cause;
        }

       
    }
}
