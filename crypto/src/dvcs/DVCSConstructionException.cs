using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Org.BouncyCastle.dvcs
{
    public class DVCSConstructionException :DVCSException
    {
        private  const long serialVersionUID = 660035299653583980L;

        public DVCSConstructionException(string message) : base(message)
        {
        }

        public DVCSConstructionException(string message, Exception cause) : base(message, cause)
        {
        }
    }
}
