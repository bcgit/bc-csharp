using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.asn1.dvcs;

namespace Org.BouncyCastle.dvcs
{
    //TODO : not ready 
    public class VPKCRequestBuilder:DVCSRequestBuilder
    {
        public VPKCRequestBuilder() : base(new DVCSRequestInformationBuilder(ServiceType.VPKC))
        {
        }


    }
}
