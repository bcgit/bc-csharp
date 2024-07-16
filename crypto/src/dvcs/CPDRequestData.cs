using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.asn1.dvcs;

namespace Org.BouncyCastle.dvcs
{
    public class CPDRequestData : DVCSRequestData
    {
        public CPDRequestData(Data data) : base(data)
        {
            InitMessage();
        }



        private void InitMessage()

        {
            if (data.GetMessage() == null)
            {
                throw new DVCSConstructionException("DVCSRequest.data.message should be specified for CPD service");
            }
        }


        public byte[] GetMessage()
        {
            return data.GetMessage().GetOctets();
        }
    }
}
