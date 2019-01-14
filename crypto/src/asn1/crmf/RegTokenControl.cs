using System;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Asn1.Crmf
{
    public class RegTokenControl:IControl
    {
        private static readonly DerObjectIdentifier type = CrmfObjectIdentifiers.id_regCtrl_regToken;
    
        private readonly DerUtf8String token;

        public RegTokenControl(DerUtf8String token)
        {
            this.token = token;
        }

        public RegTokenControl(String token)
        {
            this.token = new DerUtf8String(token);
        }

        public DerObjectIdentifier Type
        {
            get { return type; }
        }
        public Asn1Encodable Value
        {
            get { return token; }
        }
    }
}
