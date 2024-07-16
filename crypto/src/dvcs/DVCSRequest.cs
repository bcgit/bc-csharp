using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.asn1.dvcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;

namespace Org.BouncyCastle.dvcs
{
    public class DVCSRequest : DVCSMessage
    {
        private asn1.dvcs.DVCSRequest asn1;

        private DVCSRequestInfo reqInfo;

        private DVCSRequestData data;


        public Asn1Encodable Content => asn1;

        public DVCSRequestInfo RequestInfo => reqInfo;

        public DVCSRequestData Data => data;

        public GeneralName TransactionIdentifier => asn1.GetTransactionIdentifier();

        public DVCSRequest(CmsSignedData signedData) : this(SignedData.GetInstance(signedData.ContentInfo.Content).EncapContentInfo)
        {

        }

        public DVCSRequest(ContentInfo contentInfo) : base(contentInfo)
        {
            if (!DVCSObjectIdentifiers.id_ct_DVCSRequestData.Equals(contentInfo.ContentType))
            {
                throw new DVCSConstructionException("ContentInfo not a DVCS Request");
            }

            try
            {
                if (contentInfo.Content.ToAsn1Object() is Asn1Sequence)
                {
                    this.asn1 = Org.BouncyCastle.asn1.dvcs.DVCSRequest.GetInstance(contentInfo.Content);
                }
                else
                {
                    this.asn1 = Org.BouncyCastle.asn1.dvcs.DVCSRequest.GetInstance(Asn1OctetString.GetInstance(contentInfo.Content).GetOctets());
                }
            }
            catch (Exception e)
            {
                throw new DVCSConstructionException("Unable to parse content: " + e.Message, e);
            }

            this.reqInfo = new DVCSRequestInfo(asn1.GetRequestInformation());

            int service = reqInfo.ServiceType;
            if (service == ServiceType.CPD.Value.IntValue)
            {
                this.data = new CPDRequestData(asn1.GetData());
            }
            else if (service == ServiceType.VSD.Value.IntValue)
            {
                this.data = new VSDRequestData(asn1.GetData());
            }
            else if (service == ServiceType.VPKC.Value.IntValue)
            {
                this.data = new VPKCRequestData(asn1.GetData());
            }
            else if (service == ServiceType.CCPD.Value.IntValue)
            {
                this.data = new CCPDRequestData(asn1.GetData());
            }
            else
            {
                throw new DVCSConstructionException("Unknown service type: " + service);
            }

        }

        public override Asn1Encodable GetContent()
        {
            throw new NotImplementedException();
        }
    }
}
