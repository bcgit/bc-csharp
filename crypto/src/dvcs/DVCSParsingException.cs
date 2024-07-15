using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.dvcs
{
    public class DVCSParsingException :DVCSException
    {
        private const long serialVersionUID = -7895880961377691266L;
        public DVCSParsingException(string message) : base(message)
        {
        }

        public DVCSParsingException(string message, Exception cause) : base(message, cause)
        {
        }
    }
}
