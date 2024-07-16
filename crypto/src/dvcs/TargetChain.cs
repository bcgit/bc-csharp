using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.asn1.dvcs;

namespace Org.BouncyCastle.dvcs
{
    public class TargetChain
    {
        private readonly TargetEtcChain certs;


        public TargetChain(TargetEtcChain chain )
        {
            certs = chain; 
        }


        public TargetEtcChain ToASN1Structure()
        {
            return certs;
        }

    }
}
