using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.asn1.dvcs;

namespace Org.BouncyCastle.dvcs
{
    public class CPDRequestBuilder : DVCSRequestBuilder
    {
        public CPDRequestBuilder() : base(new DVCSRequestInformationBuilder(ServiceType.CPD))
        {
        }

        public DVCSRequest Build(byte[] messageBytes)
        {
            Data data = new Data(messageBytes);

            return CreateDVCRequest(data);
        }
    }
}
