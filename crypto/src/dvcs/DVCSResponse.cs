using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.asn1.dvcs;
using Org.BouncyCastle.Cms;


namespace Org.BouncyCastle.dvcs
{
    internal class DVCSResponse : DVCSMessage
    {
        private Org.BouncyCastle.asn1.dvcs.DVCSResponse asn1;


        public DVCSResponse(CmsSignedData signedData) : this(SignedData.GetInstance(signedData.ContentInfo.Content).EncapContentInfo) 
        {

        }

        public DVCSResponse(ContentInfo contentInfo) : base(contentInfo)
        {
            if (!DVCSObjectIdentifiers.id_ct_DVCSResponseData.Equals(contentInfo.ContentType))
            {
                throw new DVCSConstructionException("ContentInfo not a DVCS Response");
            }

            try
            {
                if (contentInfo.Content.ToAsn1Object() is  Asn1Sequence)
                {
                    this.asn1 = Org.BouncyCastle.asn1.dvcs.DVCSResponse.GetInstance(contentInfo.Content);
                }
                else
                {
                    this.asn1 = Org.BouncyCastle.asn1.dvcs.DVCSResponse.GetInstance(Asn1OctetString.GetInstance(contentInfo.Content).GetOctets());
                }
            }
            catch (Exception e)
            {
                throw new DVCSConstructionException("Unable to parse content: " + e.Message, e);
            }
        }

        public override Asn1Encodable GetContent()
        {
            return asn1;
        }
    }
}
