using System;

using Org.BouncyCastle.Asn1.Iana;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The KeyPurposeID object.</summary>
    /// <remarks>
    /// <code>
    /// KeyPurposeID ::= OBJECT IDENTIFIER
    /// </code>
    /// </remarks>
    // TODO[api] This class isn't needed, only the OID registry
    public sealed class KeyPurposeID
        : DerObjectIdentifier
    {
        private static readonly string id_kp = X509ObjectIdentifiers.IdPkix.Branch("3").GetID();

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
        public static readonly KeyPurposeID id_kp_secureShellClient = new KeyPurposeID(id_kp + ".21");
        public static readonly KeyPurposeID id_kp_secureShellServer = new KeyPurposeID(id_kp + ".22");

        public static readonly KeyPurposeID id_kp_cmcCA = new KeyPurposeID(id_kp + ".27");
        public static readonly KeyPurposeID id_kp_cmcRA = new KeyPurposeID(id_kp + ".28");
        public static readonly KeyPurposeID id_kp_cmcArchive = new KeyPurposeID(id_kp + ".29");
        public static readonly KeyPurposeID id_kp_cmKGA = new KeyPurposeID(id_kp + ".32");

        /// <summary>RFC 9174 sec. 4.4.1 - Delay-Tolerant Networking bundle security (TCPCLv4).</summary>
        /// <remarks><code>id-kp-bundleSecurity OBJECT IDENTIFIER ::= { id-kp 35 }</code></remarks>
        public static readonly KeyPurposeID id_kp_bundleSecurity = new KeyPurposeID(id_kp + ".35");

        /// <summary>RFC 9336 sec. 3.1 - signing documents (e.g. PDF, XML, JSON) for human consumption.</summary>
        /// <remarks><code>id-kp-documentSigning OBJECT IDENTIFIER ::= { id-kp 36 }</code></remarks>
        public static readonly KeyPurposeID id_kp_documentSigning = new KeyPurposeID(id_kp + ".36");

        /// <summary>
        /// RFC 9509 sec. 3 - signing the JWT Claims Set of a Client Credentials Assertion (CCA) using JWS, for 5G
        /// Network Function service consumers.
        /// </summary>
        /// <remarks><code>id-kp-jwt OBJECT IDENTIFIER ::= { id-kp 37 }</code></remarks>
        public static readonly KeyPurposeID id_kp_jwt = new KeyPurposeID(id_kp + ".37");

        /// <summary>
        /// RFC 9509 sec. 3 - encrypting JSON objects in HTTP messages between 5G Security Edge Protection Proxies
        /// (SEPPs) using JWE.
        /// </summary>
        /// <remarks><code>id-kp-httpContentEncrypt OBJECT IDENTIFIER ::= { id-kp 38 }</code></remarks>
        public static readonly KeyPurposeID id_kp_httpContentEncrypt = new KeyPurposeID(id_kp + ".38");

        /// <summary>
        /// RFC 9509 sec. 3 - signing OAuth 2.0 access tokens for service authorization using JWS, as issued by a 5G
        /// Network Repository Function (NRF).
        /// </summary>
        /// <remarks><code>id-kp-oauthAccessTokenSigning OBJECT IDENTIFIER ::= { id-kp 39 }</code></remarks>
        public static readonly KeyPurposeID id_kp_oauthAccessTokenSigning = new KeyPurposeID(id_kp + ".39");

        /// <summary>
        /// RFC 9734 sec. 3 - proving the identity of an Instant Messaging (IM) client, whose IM URI (RFC 3860) or XMPP
        /// URI (RFC 6121) appears in the subjectAltName.
        /// </summary>
        /// <remarks><code>id-kp-imUri OBJECT IDENTIFIER ::= { id-kp 40 }</code></remarks>
        public static readonly KeyPurposeID id_kp_imUri = new KeyPurposeID(id_kp + ".40");

        /// <summary>RFC 9809 sec. 3 - signing general-purpose configuration files.</summary>
        /// <remarks><code>id-kp-configSigning OBJECT IDENTIFIER ::= { id-kp 41 }</code></remarks>
        public static readonly KeyPurposeID id_kp_configSigning = new KeyPurposeID(id_kp + ".41");

        /// <summary>RFC 9809 sec. 3 - signing trust anchor configuration files.</summary>
        /// <remarks><code>id-kp-trustAnchorConfigSigning OBJECT IDENTIFIER ::= { id-kp 42 }</code></remarks>
        public static readonly KeyPurposeID id_kp_trustAnchorConfigSigning = new KeyPurposeID(id_kp + ".42");

        /// <summary>RFC 9809 sec. 3 - signing software or firmware update packages.</summary>
        /// <remarks><code>id-kp-updatePackageSigning OBJECT IDENTIFIER ::= { id-kp 43 }</code></remarks>
        public static readonly KeyPurposeID id_kp_updatePackageSigning = new KeyPurposeID(id_kp + ".43");

        /// <summary>RFC 9809 sec. 3 - authenticating communication peers for safety-critical communication.</summary>
        /// <remarks><code>id-kp-safetyCommunication OBJECT IDENTIFIER ::= { id-kp 44 }</code></remarks>
        public static readonly KeyPurposeID id_kp_safetyCommunication = new KeyPurposeID(id_kp + ".44");

        //
        // microsoft key purpose ids
        //

        public static readonly KeyPurposeID id_kp_smartcardlogon = new KeyPurposeID("1.3.6.1.4.1.311.20.2.2");

        public static readonly KeyPurposeID id_kp_macAddress = new KeyPurposeID("1.3.6.1.1.1.1.22");

        /// <summary>Microsoft Server Gated Crypto (msSGC).</summary>
        /// <remarks>see https://www.alvestrand.no/objectid/1.3.6.1.4.1.311.10.3.3.html</remarks>
        public static readonly KeyPurposeID id_kp_msSGC = new KeyPurposeID("1.3.6.1.4.1.311.10.3.3");

        /// <summary>Netscape Server Gated Crypto (nsSGC).</summary>
        /// <remarks>see https://www.alvestrand.no/objectid/2.16.840.1.113730.4.1.html</remarks>
        public static readonly KeyPurposeID id_kp_nsSGC = new KeyPurposeID("2.16.840.1.113730.4.1");

        //
        // kerberos PKINIT key purpose ids
        //

        private static readonly string id_pkinit = IanaObjectIdentifiers.id_pkinit.GetID();

        public static readonly KeyPurposeID scSysNodeNumber = new KeyPurposeID(id_pkinit + ".0");
        public static readonly KeyPurposeID id_pkinit_authData = new KeyPurposeID(id_pkinit + ".1");
        public static readonly KeyPurposeID id_pkinit_DHKeyData = new KeyPurposeID(id_pkinit + ".2");
        public static readonly KeyPurposeID id_pkinit_rkeyData = new KeyPurposeID(id_pkinit + ".3");
        public static readonly KeyPurposeID id_kp_pkinitClientAuth = new KeyPurposeID(id_pkinit + ".4");
        public static readonly KeyPurposeID id_kp_pkinitKdc = new KeyPurposeID(id_pkinit + ".5");

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

        [Obsolete("Use 'id_kp_pkinitClientAuth' instead")]
        public static readonly KeyPurposeID keyPurposeClientAuth = id_kp_pkinitClientAuth;
        [Obsolete("Use 'id_kp_pkinitKdc' instead")]
        public static readonly KeyPurposeID keyPurposeKdc = id_kp_pkinitKdc;
    }
}
