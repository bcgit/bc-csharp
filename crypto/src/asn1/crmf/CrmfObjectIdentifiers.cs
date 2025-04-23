using System;

using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    // TODO[api] Make static
    public abstract class CrmfObjectIdentifiers
    {
        public static readonly DerObjectIdentifier passwordBasedMac = MiscObjectIdentifiers.Entrust.Branch("66.13");

        public static readonly DerObjectIdentifier id_pkix = X509ObjectIdentifiers.IdPkix;

        // arc for Internet X.509 PKI protocols and their components
        public static readonly DerObjectIdentifier id_pkip = id_pkix.Branch("5");

        public static readonly DerObjectIdentifier id_regCtrl = id_pkip.Branch("1");
        public static readonly DerObjectIdentifier id_regCtrl_regToken = id_regCtrl.Branch("1");
        public static readonly DerObjectIdentifier id_regCtrl_authenticator = id_regCtrl.Branch("2");
        public static readonly DerObjectIdentifier id_regCtrl_pkiPublicationInfo = id_regCtrl.Branch("3");
        public static readonly DerObjectIdentifier id_regCtrl_pkiArchiveOptions = id_regCtrl.Branch("4");
        public static readonly DerObjectIdentifier id_regCtrl_oldCertID = id_regCtrl.Branch("5");
        public static readonly DerObjectIdentifier id_regCtrl_protocolEncrKey = id_regCtrl.Branch("6");

        public static readonly DerObjectIdentifier id_regInfo = id_pkip.Branch("2");
        public static readonly DerObjectIdentifier id_regInfo_utf8Pairs = id_regInfo.Branch("1");
        public static readonly DerObjectIdentifier id_regInfo_certReq = id_regInfo.Branch("2");

        public static readonly DerObjectIdentifier id_ct_encKeyWithID = PkcsObjectIdentifiers.id_ct.Branch("21");

        public static readonly DerObjectIdentifier id_dh_sig_hmac_sha1 = X509ObjectIdentifiers.pkix_algorithms.Branch("3");
        public static readonly DerObjectIdentifier id_alg_dh_pop = X509ObjectIdentifiers.pkix_algorithms.Branch("4");
    }
}
