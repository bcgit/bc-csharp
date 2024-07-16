using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.asn1.dvcs;
using Org.BouncyCastle.Cms;

namespace Org.BouncyCastle.dvcs
{
    public class VSDRequestData : DVCSRequestData
    {
        private CmsSignedData doc;

        public VSDRequestData(Data data) : base(data)
        {
            InitDocument();
        }


        private void InitDocument()

        {
            if (doc == null)
            {
                if (data.GetMessage() == null)
                {
                    throw new DVCSConstructionException("DVCSRequest.data.message should be specified for VSD service");
                }
                try
                {
                    doc = new CmsSignedData(data.GetMessage().GetOctets());
                }
                catch (CmsException e)
                {
                    throw new DVCSConstructionException("Can't read CMS SignedData from input", e);
                }
            }
        }


        public byte[] GetMessage()
        {
            return data.GetMessage().GetOctets();
        }


        public CmsSignedData GetParsedMessage()
        {
            return doc;
        }
    }
}
