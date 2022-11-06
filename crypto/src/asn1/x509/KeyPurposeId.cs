using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The KeyPurposeID object.
     * <pre>
     *     KeyPurposeID ::= OBJECT IDENTIFIER
     * </pre>
     */
    public sealed class KeyPurposeID
        : DerObjectIdentifier
    {
        private const string id_kp = "1.3.6.1.5.5.7.3";

		private KeyPurposeID(string id)
			: base(id)
        {
        }

		public static readonly KeyPurposeID AnyExtendedKeyUsage = new KeyPurposeID(X509Extensions.ExtendedKeyUsage.Id + ".0");

        public static readonly KeyPurposeID id_kp_serverAuth = new KeyPurposeID(id_kp + ".1");
        public static readonly KeyPurposeID id_kp_clientAuth = new KeyPurposeID(id_kp + ".2");
        public static readonly KeyPurposeID id_kp_codeSigning = new KeyPurposeID(id_kp + ".3");
        public static readonly KeyPurposeID id_kp_emailProtection = new KeyPurposeID(id_kp + ".4");
        public static readonly KeyPurposeID id_kp_ipsecEndSystem = new KeyPurposeID(id_kp + ".5");
        public static readonly KeyPurposeID id_kp_ipsecTunnel = new KeyPurposeID(id_kp + ".6");
        public static readonly KeyPurposeID id_kp_ipsecUser = new KeyPurposeID(id_kp + ".7");
        public static readonly KeyPurposeID id_kp_timeStamping = new KeyPurposeID(id_kp + ".8");
        public static readonly KeyPurposeID id_kp_OCSPSigning = new KeyPurposeID(id_kp + ".9");
        public static readonly KeyPurposeID id_kp_dvcs = new KeyPurposeID(id_kp + ".10");
        public static readonly KeyPurposeID id_kp_sbgpCertAAServerAuth = new KeyPurposeID(id_kp + ".11");
        public static readonly KeyPurposeID id_kp_scvp_responder = new KeyPurposeID(id_kp + ".12");
        public static readonly KeyPurposeID id_kp_eapOverPPP = new KeyPurposeID(id_kp + ".13");
        public static readonly KeyPurposeID id_kp_eapOverLAN = new KeyPurposeID(id_kp + ".14");
        public static readonly KeyPurposeID id_kp_scvpServer = new KeyPurposeID(id_kp + ".15");
        public static readonly KeyPurposeID id_kp_scvpClient = new KeyPurposeID(id_kp + ".16");
        public static readonly KeyPurposeID id_kp_ipsecIKE = new KeyPurposeID(id_kp + ".17");
        public static readonly KeyPurposeID id_kp_capwapAC = new KeyPurposeID(id_kp + ".18");
        public static readonly KeyPurposeID id_kp_capwapWTP = new KeyPurposeID(id_kp + ".19");

        public static readonly KeyPurposeID id_kp_cmcCA = new KeyPurposeID(id_kp + ".27");
        public static readonly KeyPurposeID id_kp_cmcRA = new KeyPurposeID(id_kp + ".28");
        public static readonly KeyPurposeID id_kp_cmKGA = new KeyPurposeID(id_kp + ".32");

        //
        // microsoft key purpose ids
        //
        public static readonly KeyPurposeID id_kp_smartcardlogon = new KeyPurposeID("1.3.6.1.4.1.311.20.2.2");

        public static readonly KeyPurposeID id_kp_macAddress = new KeyPurposeID("1.3.6.1.1.1.1.22");

        /// <summary>Microsoft Server Gated Crypto (msSGC).</summary>
        /// <remarks>see https://www.alvestrand.no/objectid/1.3.6.1.4.1.311.10.3.3.html</remarks>
        public static readonly KeyPurposeID id_kp_msSGC = new KeyPurposeID("1.3.6.1.4.1.311.10.3.3");

        private const string id_pkinit = "1.3.6.1.5.2.3";

        public static readonly KeyPurposeID scSysNodeNumber = new KeyPurposeID(id_pkinit + ".0");
        public static readonly KeyPurposeID id_pkinit_authData = new KeyPurposeID(id_pkinit + ".1");
        public static readonly KeyPurposeID id_pkinit_DHKeyData = new KeyPurposeID(id_pkinit + ".2");
        public static readonly KeyPurposeID id_pkinit_rkeyData = new KeyPurposeID(id_pkinit + ".3");
        public static readonly KeyPurposeID keyPurposeClientAuth = new KeyPurposeID(id_pkinit + ".4");
        public static readonly KeyPurposeID keyPurposeKdc = new KeyPurposeID(id_pkinit + ".5");

        /// <summary>Netscape Server Gated Crypto (nsSGC).</summary>
        /// <remarks>see https://www.alvestrand.no/objectid/2.16.840.1.113730.4.1.html</remarks>
        public static readonly KeyPurposeID id_kp_nsSGC = new KeyPurposeID("2.16.840.1.113730.4.1");

        [Obsolete("Use 'id_kp_serverAuth' instead")]
        public static readonly KeyPurposeID IdKPServerAuth = id_kp_serverAuth;
        [Obsolete("Use 'id_kp_clientAuth' instead")]
        public static readonly KeyPurposeID IdKPClientAuth = id_kp_clientAuth;
        [Obsolete("Use 'id_kp_codeSigning' instead")]
        public static readonly KeyPurposeID IdKPCodeSigning = id_kp_codeSigning;
        [Obsolete("Use 'id_kp_emailProtection' instead")]
        public static readonly KeyPurposeID IdKPEmailProtection = id_kp_emailProtection;
        [Obsolete("Use 'id_kp_ipsecEndSystem' instead")]
        public static readonly KeyPurposeID IdKPIpsecEndSystem = id_kp_ipsecEndSystem;
        [Obsolete("Use 'id_kp_ipsecTunnel' instead")]
        public static readonly KeyPurposeID IdKPIpsecTunnel = id_kp_ipsecTunnel;
        [Obsolete("Use 'id_kp_ipsecUser' instead")]
        public static readonly KeyPurposeID IdKPIpsecUser = id_kp_ipsecUser;
        [Obsolete("Use 'id_kp_timeStamping' instead")]
        public static readonly KeyPurposeID IdKPTimeStamping = id_kp_timeStamping;
        [Obsolete("Use 'id_kp_OCSPSigning' instead")]
        public static readonly KeyPurposeID IdKPOcspSigning = id_kp_OCSPSigning;

        [Obsolete("Use 'id_kp_smartcardlogon' instead")]
        public static readonly KeyPurposeID IdKPSmartCardLogon = id_kp_smartcardlogon;

        [Obsolete("Use 'id_kp_macAddress' instead")]
        public static readonly KeyPurposeID IdKPMacAddress = id_kp_macAddress;
    }
}
