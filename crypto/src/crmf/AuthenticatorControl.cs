using System;
using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Crmf
{
    public class AuthenticatorControl:IControl
    {

        private static readonly DerObjectIdentifier type = CrmfObjectIdentifiers.id_regCtrl_authenticator;

        private readonly DerUtf8String token;

        public AuthenticatorControl(DerUtf8String token)
        {
            this.token = token;
        }

        public AuthenticatorControl(String token)
        {
            this.token = new DerUtf8String(token);
        }

        public DerObjectIdentifier Type
        {
            get { return type; }
        }

        public Asn1Encodable Value {
            get { return token; }
        }
    }
}
