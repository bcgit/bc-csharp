using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.asn1.dvcs;

namespace Org.BouncyCastle.dvcs
{ 
    
/*
Verify Public Key Certificates. TODO:chech  the generic type 
 */
    public class VPKCRequestData :DVCSRequestData
    {
        private IList<TargetChain> _chains;
        public VPKCRequestData(Data data) : base(data)
        {
            TargetEtcChain[] certs = data.GetCerts();

            if (certs == null)
            {
                throw new DVCSConstructionException("DVCSRequest.data.certs should be specified for VPKC service");
            }

            _chains = new List<TargetChain>(certs.Length);

            for (int i = 0; i != certs.Length; i++)
            {
                _chains.Add(new TargetChain(certs[i]));
            }

        }
        public IList GetCerts()
        {
            return new ReadOnlyCollection<TargetChain>(_chains); 
        }


    }
}
