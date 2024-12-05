using System;

using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
	public static class CmpObjectIdentifiers
	{
        // RFC 4210

        /**
         * id-PasswordBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 13}
         */
        public static readonly DerObjectIdentifier passwordBasedMac = CrmfObjectIdentifiers.passwordBasedMac;

        /**
         * id-KemBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 16}
         */
        public static readonly DerObjectIdentifier kemBasedMac = MiscObjectIdentifiers.Entrust.Branch("66.16");

        /**
         * id-DHBasedMac OBJECT IDENTIFIER ::= {1 2 840 113533 7 66 30}
         */
        public static readonly DerObjectIdentifier dhBasedMac = MiscObjectIdentifiers.Entrust.Branch("66.30");

        // Example InfoTypeAndValue contents include, but are not limited
        // to, the following (un-comment in this ASN.1 module and use as
        // appropriate for a given environment):
        //
        //   id-it-caProtEncCert    OBJECT IDENTIFIER ::= {id-it 1}
        //      CAProtEncCertValue      ::= CMPCertificate
        //   id-it-signKeyPairTypes OBJECT IDENTIFIER ::= {id-it 2}
        //      SignKeyPairTypesValue   ::= SEQUENCE OF AlgorithmIdentifier
        //   id-it-encKeyPairTypes  OBJECT IDENTIFIER ::= {id-it 3}
        //      EncKeyPairTypesValue    ::= SEQUENCE OF AlgorithmIdentifier
        //   id-it-preferredSymmAlg OBJECT IDENTIFIER ::= {id-it 4}
        //      PreferredSymmAlgValue   ::= AlgorithmIdentifier
        //   id-it-caKeyUpdateInfo  OBJECT IDENTIFIER ::= {id-it 5}
        //      CAKeyUpdateInfoValue    ::= CAKeyUpdAnnContent
        //   id-it-currentCRL       OBJECT IDENTIFIER ::= {id-it 6}
        //      CurrentCRLValue         ::= CertificateList
        //   id-it-unsupportedOIDs  OBJECT IDENTIFIER ::= {id-it 7}
        //      UnsupportedOIDsValue    ::= SEQUENCE OF OBJECT IDENTIFIER
        //   id-it-keyPairParamReq  OBJECT IDENTIFIER ::= {id-it 10}
        //      KeyPairParamReqValue    ::= OBJECT IDENTIFIER
        //   id-it-keyPairParamRep  OBJECT IDENTIFIER ::= {id-it 11}
        //      KeyPairParamRepValue    ::= AlgorithmIdentifer
        //   id-it-revPassphrase    OBJECT IDENTIFIER ::= {id-it 12}
        //      RevPassphraseValue      ::= EncryptedValue
        //   id-it-implicitConfirm  OBJECT IDENTIFIER ::= {id-it 13}
        //      ImplicitConfirmValue    ::= NULL
        //   id-it-confirmWaitTime  OBJECT IDENTIFIER ::= {id-it 14}
        //      ConfirmWaitTimeValue    ::= GeneralizedTime
        //   id-it-origPKIMessage   OBJECT IDENTIFIER ::= {id-it 15}
        //      OrigPKIMessageValue     ::= PKIMessages
        //   id-it-suppLangTags     OBJECT IDENTIFIER ::= {id-it 16}
        //      SuppLangTagsValue       ::= SEQUENCE OF UTF8String
        //   id-it-certProfile  OBJECT IDENTIFIER ::= {id-it 21}
        //      CertProfileValue ::= SEQUENCE SIZE (1..MAX) OF UTF8String
        // where
        //
        //   id-pkix OBJECT IDENTIFIER ::= {
        //      iso(1) identified-organization(3)
        //      dod(6) internet(1) security(5) mechanisms(5) pkix(7)}
        // and
        //   id-it   OBJECT IDENTIFIER ::= {id-pkix 4}

        /** RFC 4120: id-it: PKIX.4 = 1.3.6.1.5.5.7.4 */
        public static readonly DerObjectIdentifier id_it = X509ObjectIdentifiers.IdPkix.Branch("4");

        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.1
         */
        public static readonly DerObjectIdentifier it_caProtEncCert = id_it.Branch("1");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.2
         */
        public static readonly DerObjectIdentifier it_signKeyPairTypes = id_it.Branch("2");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.3
         */
        public static readonly DerObjectIdentifier it_encKeyPairTypes = id_it.Branch("3");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.4
         */
        public static readonly DerObjectIdentifier it_preferredSymAlg = id_it.Branch("4");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.5
         */
        public static readonly DerObjectIdentifier it_caKeyUpdateInfo = id_it.Branch("5");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.6
         */
        public static readonly DerObjectIdentifier it_currentCRL = id_it.Branch("6");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.7
         */
        public static readonly DerObjectIdentifier it_unsupportedOIDs = id_it.Branch("7");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.10
         */
        public static readonly DerObjectIdentifier it_keyPairParamReq = id_it.Branch("10");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.11
         */
        public static readonly DerObjectIdentifier it_keyPairParamRep = id_it.Branch("11");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.12
         */
        public static readonly DerObjectIdentifier it_revPassphrase = id_it.Branch("12");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.13
         */
        public static readonly DerObjectIdentifier it_implicitConfirm = id_it.Branch("13");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.14
         */
        public static readonly DerObjectIdentifier it_confirmWaitTime = id_it.Branch("14");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.15
         */
        public static readonly DerObjectIdentifier it_origPKIMessage = id_it.Branch("15");
        /**
         * RFC 4120: 1.3.6.1.5.5.7.4.16
         */
        public static readonly DerObjectIdentifier it_suppLangTags = id_it.Branch("16");

        /**
         * Update 16, RFC 4210
         * {id-it 17}
         */
        public static readonly DerObjectIdentifier id_it_caCerts = id_it.Branch("17");


        /**
         * Update 16, RFC 4210
         * GenRep:    {id-it 18}, RootCaKeyUpdateContent
         */
        public static readonly DerObjectIdentifier id_it_rootCaKeyUpdate = id_it.Branch("18");


        /**
         * Update 16, RFC 4210
         * {id-it 19}
         */
        public static readonly DerObjectIdentifier id_it_certReqTemplate = id_it.Branch("19");


        /**
         * Update 16, RFC 4210
         * GenMsg:    {id-it 20}, RootCaCertValue
         */
        public static readonly DerObjectIdentifier id_it_rootCaCert = id_it.Branch("20");

        /**
         * Update-16 to RFC 4210
         * id-it-certProfile  OBJECT IDENTIFIER ::= {id-it 21}
         */
        public static readonly DerObjectIdentifier id_it_certProfile = id_it.Branch("21");

        public static readonly DerObjectIdentifier id_it_crlStatusList = id_it.Branch("22");

        public static readonly DerObjectIdentifier id_it_crls = id_it.Branch("23");

        // TODO Update once OID allocated.
#if false
        /**
         * id-it-KemCiphertextInfo OBJECT IDENTIFIER ::= { id-it TBD1 }
         */
        public static readonly DerObjectIdentifier id_it_KemCiphertextInfo = id_it.Branch("TBD1");
#endif

        // RFC 4211

        // id-pkix  OBJECT IDENTIFIER  ::= { iso(1) identified-organization(3)
        //     dod(6) internet(1) security(5) mechanisms(5) pkix(7) }
        //
        // arc for Internet X.509 PKI protocols and their components
        // id-pkip  OBJECT IDENTIFIER :: { id-pkix pkip(5) }
        //
        // arc for Registration Controls in CRMF
        // id-regCtrl  OBJECT IDENTIFIER ::= { id-pkip regCtrl(1) }
        //
        // arc for Registration Info in CRMF
        // id-regInfo       OBJECT IDENTIFIER ::= { id-pkip id-regInfo(2) }

        /**
         * RFC 4211: it-pkip: PKIX.5 = 1.3.6.1.5.5.7.5
         */
        public static readonly DerObjectIdentifier id_pkip = CrmfObjectIdentifiers.id_pkip;

        /**
         * RFC 4211: it-regCtrl: 1.3.6.1.5.5.7.5.1
         */
        public static readonly DerObjectIdentifier id_regCtrl = CrmfObjectIdentifiers.id_regCtrl;

        /**
         * RFC 4211: it-regInfo: 1.3.6.1.5.5.7.5.2
         */
        public static readonly DerObjectIdentifier id_regInfo = CrmfObjectIdentifiers.id_regInfo;


        /**
         * 1.3.6.1.5.5.7.5.1.1
         */
        public static readonly DerObjectIdentifier regCtrl_regToken = CrmfObjectIdentifiers.id_regCtrl_regToken;
        /**
         * 1.3.6.1.5.5.7.5.1.2
         */
        public static readonly DerObjectIdentifier regCtrl_authenticator = CrmfObjectIdentifiers.id_regCtrl_authenticator;
        /**
         * 1.3.6.1.5.5.7.5.1.3
         */
        public static readonly DerObjectIdentifier regCtrl_pkiPublicationInfo = CrmfObjectIdentifiers.id_regCtrl_pkiPublicationInfo;
        /**
         * 1.3.6.1.5.5.7.5.1.4
         */
        public static readonly DerObjectIdentifier regCtrl_pkiArchiveOptions = CrmfObjectIdentifiers.id_regCtrl_pkiArchiveOptions;
        /**
         * 1.3.6.1.5.5.7.5.1.5
         */
        public static readonly DerObjectIdentifier regCtrl_oldCertID = CrmfObjectIdentifiers.id_regCtrl_oldCertID;
        /**
         * 1.3.6.1.5.5.7.5.1.6
         */
        public static readonly DerObjectIdentifier regCtrl_protocolEncrKey = CrmfObjectIdentifiers.id_regCtrl_protocolEncrKey;

        /**
         * From RFC4210:
         * id-regCtrl-altCertTemplate OBJECT IDENTIFIER ::= {id-regCtrl 7}; 1.3.6.1.5.5.7.1.7
         */
        public static readonly DerObjectIdentifier regCtrl_altCertTemplate = id_regCtrl.Branch("7");

        /**
         * id-regCtrl-algId OBJECT IDENTIFIER ::= { iso(1)
         * identified-organization(3) dod(6) internet(1) security(5)
         * mechanisms(5) pkix(7) pkip(5) regCtrl(1) 11 }
         */
        public static readonly DerObjectIdentifier id_regCtrl_algId = id_regCtrl.Branch("11");

        /**
         * id-regCtrl-rsaKeyLen OBJECT IDENTIFIER ::= { iso(1)
         * identified-organization(3) dod(6) internet(1) security(5)
         * mechanisms(5) pkix(7) pkip(5) regCtrl(1) 12 }
         */
        public static readonly DerObjectIdentifier id_regCtrl_rsaKeyLen = id_regCtrl.Branch("12");

        /**
         * RFC 4211: it-regInfo-utf8Pairs: 1.3.6.1.5.5.7.5.2.1
         */
        public static readonly DerObjectIdentifier regInfo_utf8Pairs = CrmfObjectIdentifiers.id_regInfo_utf8Pairs;
        /**
         * RFC 4211: it-regInfo-certReq: 1.3.6.1.5.5.7.5.2.1
         */
        public static readonly DerObjectIdentifier regInfo_certReq = CrmfObjectIdentifiers.id_regInfo_certReq;

        /**
         * 1.2.840.113549.1.9.16.1.21
         * <p>
         * id-ct   OBJECT IDENTIFIER ::= { id-smime  1 }  -- content types
         * </p><p>
         * id-ct-encKeyWithID OBJECT IDENTIFIER ::= {id-ct 21}
         * </p>
         */
        public static readonly DerObjectIdentifier ct_encKeyWithID = CrmfObjectIdentifiers.id_ct_encKeyWithID;
    }
}
