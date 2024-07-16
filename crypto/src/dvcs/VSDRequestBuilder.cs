using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.asn1.dvcs;
using Org.BouncyCastle.Cms;

namespace Org.BouncyCastle.dvcs
{
    public class VSDRequestBuilder : DVCSRequestBuilder
    {
        public VSDRequestBuilder() : base(new DVCSRequestInformationBuilder(ServiceType.VSD))
        {
        }

        public void SetRequestTime(DateTime requestTime)
        {
            requestInformationBuilder.RequestTime = new DVCSTime(requestTime);
        }


        public DVCSRequest build(CmsSignedData document)
        {
            try
            {
                Data data = new Data(document.GetEncoded());

                return CreateDVCRequest(data);
            }
            catch (IOException e)
            {
                throw new DVCSException("Failed to encode CMS signed data", e);
            }
        }
    }
}
