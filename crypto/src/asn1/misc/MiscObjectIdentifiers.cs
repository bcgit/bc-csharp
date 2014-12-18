namespace Org.BouncyCastle.Asn1.Misc
{
    public abstract class MiscObjectIdentifiers
    {
        //
        // Netscape
        //       iso/itu(2) joint-assign(16) us(840) uscompany(1) Netscape(113730) cert-extensions(1) }
        //
        public static readonly DerObjectIdentifier Netscape                = new DerObjectIdentifier("2.16.840.1.113730.1");
        public static readonly DerObjectIdentifier NetscapeCertType        = Netscape.Branch("1");
        public static readonly DerObjectIdentifier NetscapeBaseUrl         = Netscape.Branch("2");
        public static readonly DerObjectIdentifier NetscapeRevocationUrl   = Netscape.Branch("3");
        public static readonly DerObjectIdentifier NetscapeCARevocationUrl = Netscape.Branch("4");
        public static readonly DerObjectIdentifier NetscapeRenewalUrl      = Netscape.Branch("7");
        public static readonly DerObjectIdentifier NetscapeCAPolicyUrl     = Netscape.Branch("8");
        public static readonly DerObjectIdentifier NetscapeSslServerName   = Netscape.Branch("12");
        public static readonly DerObjectIdentifier NetscapeCertComment     = Netscape.Branch("13");

        //
        // Verisign
        //       iso/itu(2) joint-assign(16) us(840) uscompany(1) verisign(113733) cert-extensions(1) }
        //
        public static readonly DerObjectIdentifier Verisign = new DerObjectIdentifier("2.16.840.1.113733.1");

        //
        // CZAG - country, zip, age, and gender
        //
        public static readonly DerObjectIdentifier VerisignCzagExtension          = Verisign.Branch("6.3");

        public static readonly DerObjectIdentifier VerisignPrivate_6_9            = Verisign.Branch("6.9");
        public static readonly DerObjectIdentifier VerisignOnSiteJurisdictionHash = Verisign.Branch("6.11");
        public static readonly DerObjectIdentifier VerisignBitString_6_13         = Verisign.Branch("6.13");

        // D&B D-U-N-S number
        public static readonly DerObjectIdentifier VerisignDnbDunsNumber          = Verisign.Branch("6.15");

        public static readonly DerObjectIdentifier VerisignIssStrongCrypto        = Verisign.Branch("8.1");

        //
        // Novell
        //       iso/itu(2) country(16) us(840) organization(1) novell(113719)
        //
        public static readonly string				Novell					= "2.16.840.1.113719";
        public static readonly DerObjectIdentifier	NovellSecurityAttribs	= new DerObjectIdentifier(Novell + ".1.9.4.1");

        //
        // Entrust
        //       iso(1) member-body(16) us(840) nortelnetworks(113533) entrust(7)
        //
        public static readonly string				Entrust					= "1.2.840.113533.7";
        public static readonly DerObjectIdentifier	EntrustVersionExtension = new DerObjectIdentifier(Entrust + ".65.0");
    }
}
