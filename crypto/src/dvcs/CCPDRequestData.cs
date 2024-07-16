using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.asn1.dvcs;

namespace Org.BouncyCastle.dvcs
{
    public class CCPDRequestData : DVCSRequestData
    {
        public CCPDRequestData(Data data) : base(data)
        {
            InitDigest();
        }



        private void InitDigest()

        {
            if (data.GetMessageImprint() == null)
            {
                throw new DVCSConstructionException("DVCSRequest.data.messageImprint should be specified for CCPD service");
            }
        }

      
        public MessageImprint GetMessageImprint()
        {
            return new MessageImprint(data.GetMessageImprint());
        }
    }
}
