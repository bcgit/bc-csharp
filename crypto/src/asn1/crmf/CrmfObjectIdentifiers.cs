using System;

using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>Object identifiers for CRMF (RFC 4211).</summary>
    // TODO[api] Make static
    public abstract class CrmfObjectIdentifiers
    {
        /// <summary>The object identifier <c>1.2.840.113533.7.66.13</c>.</summary>
        public static readonly DerObjectIdentifier passwordBasedMac = MiscObjectIdentifiers.Entrust.Branch("66.13");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7</c>.</summary>
        public static readonly DerObjectIdentifier id_pkix = X509ObjectIdentifiers.IdPkix;

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.5</c>.</summary>
        // arc for Internet X.509 PKI protocols and their components
        public static readonly DerObjectIdentifier id_pkip = id_pkix.Branch("5");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.5.1</c>.</summary>
        public static readonly DerObjectIdentifier id_regCtrl = id_pkip.Branch("1");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.5.1.1</c>.</summary>
        public static readonly DerObjectIdentifier id_regCtrl_regToken = id_regCtrl.Branch("1");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.5.1.2</c>.</summary>
        public static readonly DerObjectIdentifier id_regCtrl_authenticator = id_regCtrl.Branch("2");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.5.1.3</c>.</summary>
        public static readonly DerObjectIdentifier id_regCtrl_pkiPublicationInfo = id_regCtrl.Branch("3");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.5.1.4</c>.</summary>
        public static readonly DerObjectIdentifier id_regCtrl_pkiArchiveOptions = id_regCtrl.Branch("4");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.5.1.5</c>.</summary>
        public static readonly DerObjectIdentifier id_regCtrl_oldCertID = id_regCtrl.Branch("5");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.5.1.6</c>.</summary>
        public static readonly DerObjectIdentifier id_regCtrl_protocolEncrKey = id_regCtrl.Branch("6");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.5.2</c>.</summary>
        public static readonly DerObjectIdentifier id_regInfo = id_pkip.Branch("2");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.5.2.1</c>.</summary>
        public static readonly DerObjectIdentifier id_regInfo_utf8Pairs = id_regInfo.Branch("1");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.5.2.2</c>.</summary>
        public static readonly DerObjectIdentifier id_regInfo_certReq = id_regInfo.Branch("2");

        /// <summary>The object identifier <c>1.2.840.113549.1.9.16.1.21</c>.</summary>
        public static readonly DerObjectIdentifier id_ct_encKeyWithID = PkcsObjectIdentifiers.id_ct.Branch("21");

        /// <summary>The object identifier <c>1.3.6.1.5.5.7.6.3</c>.</summary>
        public static readonly DerObjectIdentifier id_dh_sig_hmac_sha1 = X509ObjectIdentifiers.pkix_algorithms.Branch("3");
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.6.4</c>.</summary>
        public static readonly DerObjectIdentifier id_alg_dh_pop = X509ObjectIdentifiers.pkix_algorithms.Branch("4");
    }
}
