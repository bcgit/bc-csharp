using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.asn1.dvcs;

namespace Org.BouncyCastle.dvcs
{
    public abstract class DVCSRequestData
    {

        protected Data data;



        protected DVCSRequestData(Data data)
        {
            this.data = data;
        }

        public Data ToASN1Structure()
        {
            return data;
        }

    }
}
