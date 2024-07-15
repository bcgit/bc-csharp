using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.dvcs
{
    public abstract class DVCSMessage
    {
        private readonly ContentInfo contentInfo;


        protected DVCSMessage(ContentInfo contentInfo)
        {
            this.contentInfo = contentInfo;
        }

        public DerObjectIdentifier ContentType
        {
            get { return contentInfo.ContentType; }
        }

        public abstract Asn1Encodable GetContent();
    }
}
