using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.asn1.dvcs
{

    public static class DVCSObjectIdentifiers
    {

        /** Base OID id-pkix: 1.3.6.1.5.5.7 */
        public static readonly DerObjectIdentifier id_pkix = new DerObjectIdentifier("1.3.6.1.5.5.7");
        /** Base OID id-smime: 1.2.840.113549.1.9.16 */
        public static readonly DerObjectIdentifier id_smime = new DerObjectIdentifier("1.2.840.113549.1.9.16");

        /** Authority Information Access for DVCS; id-ad-dcvs;  OID: 1.3.6.1.5.5.7.48.4 */
        public static readonly DerObjectIdentifier id_ad_dvcs = id_pkix.Branch("48.4");

        /** Key Purpose for DVCS; id-kp-dvcs; OID: 1.3.6.1.5.5.7.3.10 */
        public static readonly DerObjectIdentifier id_kp_dvcs = id_pkix.Branch("3.10");

        /** SMIME eContentType id-ct-DVCSRequestData;   OID: 1.2.840.113549.1.9.16.1.7 */
        public static readonly DerObjectIdentifier id_ct_DVCSRequestData = id_smime.Branch("1.7");
        /** SMIME eContentType id-ct-DVCSResponseData;  OID: 1.2.840.113549.1.9.16.1.8 */
        public static readonly DerObjectIdentifier id_ct_DVCSResponseData = id_smime.Branch("1.8");

        /** SMIME DataValidation certificate attribute id-aa-dvcs-dvc;  OID: 1.2.840.113549.1.9.16.2,29 */
        public static readonly DerObjectIdentifier id_aa_dvcs_dvc = id_smime.Branch("2.29");
    }
}
