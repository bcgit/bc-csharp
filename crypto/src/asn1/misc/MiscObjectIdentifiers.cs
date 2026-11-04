namespace Org.BouncyCastle.Asn1.Misc
{
    /// <summary>Miscellaneous object identifiers, mostly from Netscape and Verisign.</summary>
    // TODO[api] Make static
    public abstract class MiscObjectIdentifiers
    {
        /// <summary>The object identifier <c>2.16.840.1.113730.1</c>.</summary>
        //
        // Netscape
        //       iso/itu(2) joint-assign(16) us(840) uscompany(1) Netscape(113730) cert-extensions(1) }
        //
        public static readonly DerObjectIdentifier Netscape                = new DerObjectIdentifier("2.16.840.1.113730.1");
        /// <summary>The object identifier <c>2.16.840.1.113730.1.1</c>.</summary>
        public static readonly DerObjectIdentifier NetscapeCertType        = Netscape.Branch("1");
        /// <summary>The object identifier <c>2.16.840.1.113730.1.2</c>.</summary>
        public static readonly DerObjectIdentifier NetscapeBaseUrl         = Netscape.Branch("2");
        /// <summary>The object identifier <c>2.16.840.1.113730.1.3</c>.</summary>
        public static readonly DerObjectIdentifier NetscapeRevocationUrl   = Netscape.Branch("3");
        /// <summary>The object identifier <c>2.16.840.1.113730.1.4</c>.</summary>
        public static readonly DerObjectIdentifier NetscapeCARevocationUrl = Netscape.Branch("4");
        /// <summary>The object identifier <c>2.16.840.1.113730.1.7</c>.</summary>
        public static readonly DerObjectIdentifier NetscapeRenewalUrl      = Netscape.Branch("7");
        /// <summary>The object identifier <c>2.16.840.1.113730.1.8</c>.</summary>
        public static readonly DerObjectIdentifier NetscapeCAPolicyUrl     = Netscape.Branch("8");
        /// <summary>The object identifier <c>2.16.840.1.113730.1.12</c>.</summary>
        public static readonly DerObjectIdentifier NetscapeSslServerName   = Netscape.Branch("12");
        /// <summary>The object identifier <c>2.16.840.1.113730.1.13</c>.</summary>
        public static readonly DerObjectIdentifier NetscapeCertComment     = Netscape.Branch("13");

        /// <summary>The object identifier <c>2.16.840.1.113733.1</c>.</summary>
        //
        // Verisign
        //       iso/itu(2) joint-assign(16) us(840) uscompany(1) verisign(113733) cert-extensions(1) }
        //
        public static readonly DerObjectIdentifier Verisign = new DerObjectIdentifier("2.16.840.1.113733.1");

        /// <summary>The object identifier <c>2.16.840.1.113733.1.6.3</c>.</summary>
        //
        // CZAG - country, zip, age, and gender
        //
        public static readonly DerObjectIdentifier VerisignCzagExtension          = Verisign.Branch("6.3");

        /// <summary>The object identifier <c>2.16.840.1.113733.1.6.9</c>.</summary>
        public static readonly DerObjectIdentifier VerisignPrivate_6_9            = Verisign.Branch("6.9");
        /// <summary>The object identifier <c>2.16.840.1.113733.1.6.11</c>.</summary>
        public static readonly DerObjectIdentifier VerisignOnSiteJurisdictionHash = Verisign.Branch("6.11");
        /// <summary>The object identifier <c>2.16.840.1.113733.1.6.13</c>.</summary>
        public static readonly DerObjectIdentifier VerisignBitString_6_13         = Verisign.Branch("6.13");

        /// <summary>The object identifier <c>2.16.840.1.113733.1.6.15</c>.</summary>
        // D&B D-U-N-S number
        public static readonly DerObjectIdentifier VerisignDnbDunsNumber          = Verisign.Branch("6.15");

        /// <summary>The object identifier <c>2.16.840.1.113733.1.8.1</c>.</summary>
        public static readonly DerObjectIdentifier VerisignIssStrongCrypto        = Verisign.Branch("8.1");

        /// <summary>The object identifier <c>2.16.840.1.113719</c>.</summary>
        //
        // Novell
        //       iso/itu(2) country(16) us(840) organization(1) novell(113719)
        //
        public static readonly DerObjectIdentifier Novell = new DerObjectIdentifier("2.16.840.1.113719");
        /// <summary>The object identifier <c>2.16.840.1.113719.1.9.4.1</c>.</summary>
        public static readonly DerObjectIdentifier NovellSecurityAttribs = Novell.Branch("1.9.4.1");

        /// <summary>The object identifier <c>1.2.840.113533.7</c>.</summary>
        //
        // Entrust
        //       iso(1) member-body(2) us(840) nortelnetworks(113533) entrust(7)
        //
        public static readonly DerObjectIdentifier Entrust = new DerObjectIdentifier("1.2.840.113533.7");
        /// <summary>The object identifier <c>1.2.840.113533.7.65.0</c>.</summary>
        public static readonly DerObjectIdentifier EntrustVersionExtension = Entrust.Branch("65.0");

        /// <summary>The object identifier <c>1.2.840.113533.7.66.10</c>.</summary>
        public static readonly DerObjectIdentifier cast5CBC = Entrust.Branch("66.10");

        /// <summary>The object identifier <c>1.3.6.1.5.5.8.1.2</c>.</summary>
        //
        // HMAC-SHA1       hMAC-SHA1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
        //       dod(6) internet(1) security(5) mechanisms(5) 8 1 2 }
        //
        public static readonly DerObjectIdentifier HMAC_SHA1 = new DerObjectIdentifier("1.3.6.1.5.5.8.1.2");

        /// <summary>The object identifier <c>1.3.6.1.4.1.188.7.1.1.2</c>.</summary>
        //
        // Ascom
        //
        public static readonly DerObjectIdentifier as_sys_sec_alg_ideaCBC = new DerObjectIdentifier("1.3.6.1.4.1.188.7.1.1.2");

        /// <summary>The object identifier <c>1.3.6.1.4.1.3029</c>.</summary>
        //
        // Peter Gutmann's Cryptlib
        //
        public static readonly DerObjectIdentifier cryptlib = new DerObjectIdentifier("1.3.6.1.4.1.3029");

        /// <summary>The object identifier <c>1.3.6.1.4.1.3029.1</c>.</summary>
        public static readonly DerObjectIdentifier cryptlib_algorithm = cryptlib.Branch("1");
        /// <summary>The object identifier <c>1.3.6.1.4.1.3029.1.1.1</c>.</summary>
        public static readonly DerObjectIdentifier cryptlib_algorithm_blowfish_ECB = cryptlib_algorithm.Branch("1.1");
        /// <summary>The object identifier <c>1.3.6.1.4.1.3029.1.1.2</c>.</summary>
        public static readonly DerObjectIdentifier cryptlib_algorithm_blowfish_CBC = cryptlib_algorithm.Branch("1.2");
        /// <summary>The object identifier <c>1.3.6.1.4.1.3029.1.1.3</c>.</summary>
        public static readonly DerObjectIdentifier cryptlib_algorithm_blowfish_CFB = cryptlib_algorithm.Branch("1.3");
        /// <summary>The object identifier <c>1.3.6.1.4.1.3029.1.1.4</c>.</summary>
        public static readonly DerObjectIdentifier cryptlib_algorithm_blowfish_OFB = cryptlib_algorithm.Branch("1.4");

        /// <summary>The object identifier <c>1.3.6.1.4.1.1722.12.2</c>.</summary>
        //
        // Blake2b
        //
        public static readonly DerObjectIdentifier blake2 = new DerObjectIdentifier("1.3.6.1.4.1.1722.12.2");

        /// <summary>The object identifier <c>1.3.6.1.4.1.1722.12.2.1.5</c>.</summary>
        public static readonly DerObjectIdentifier id_blake2b160 = blake2.Branch("1.5");
        /// <summary>The object identifier <c>1.3.6.1.4.1.1722.12.2.1.8</c>.</summary>
        public static readonly DerObjectIdentifier id_blake2b256 = blake2.Branch("1.8");
        /// <summary>The object identifier <c>1.3.6.1.4.1.1722.12.2.1.12</c>.</summary>
        public static readonly DerObjectIdentifier id_blake2b384 = blake2.Branch("1.12");
        /// <summary>The object identifier <c>1.3.6.1.4.1.1722.12.2.1.16</c>.</summary>
        public static readonly DerObjectIdentifier id_blake2b512 = blake2.Branch("1.16");

        /// <summary>The object identifier <c>1.3.6.1.4.1.1722.12.2.2.4</c>.</summary>
        public static readonly DerObjectIdentifier id_blake2s128 = blake2.Branch("2.4");
        /// <summary>The object identifier <c>1.3.6.1.4.1.1722.12.2.2.5</c>.</summary>
        public static readonly DerObjectIdentifier id_blake2s160 = blake2.Branch("2.5");
        /// <summary>The object identifier <c>1.3.6.1.4.1.1722.12.2.2.7</c>.</summary>
        public static readonly DerObjectIdentifier id_blake2s224 = blake2.Branch("2.7");
        /// <summary>The object identifier <c>1.3.6.1.4.1.1722.12.2.2.8</c>.</summary>
        public static readonly DerObjectIdentifier id_blake2s256 = blake2.Branch("2.8");

        /// <summary>The object identifier <c>1.3.6.1.4.1.1722.12.2.3</c>.</summary>
        public static readonly DerObjectIdentifier blake3 = blake2.Branch("3");

        /// <summary>The object identifier <c>1.3.6.1.4.1.1722.12.2.3.8</c>.</summary>
        public static readonly DerObjectIdentifier blake3_256 = blake3.Branch("8");

        /// <summary>The object identifier <c>1.3.6.1.4.1.11591.4.11</c>.</summary>
        //
        // Scrypt
        public static readonly DerObjectIdentifier id_scrypt = new DerObjectIdentifier("1.3.6.1.4.1.11591.4.11");

        /// <summary>The object identifier <c>1.3.6.1.4.1.18227.2.1</c>.</summary>
        // Composite key/signature oid - prototyping
        //
        //    id-alg-composite OBJECT IDENTIFIER ::= {
        //        iso(1)  identified-organization(3) dod(6) internet(1) private(4)
        //        enterprise(1) OpenCA(18227) Algorithms(2) id-alg-composite(1) }
        public static readonly DerObjectIdentifier id_alg_composite = new DerObjectIdentifier("1.3.6.1.4.1.18227.2.1");

        /// <summary>The object identifier <c>2.16.840.1.114027.80.4.1</c>.</summary>
        // -- To be replaced by IANA
        //
        //id-composite-key OBJECT IDENTIFIER ::= {
        //
        //    joint-iso-itu-t(2) country(16) us(840) organization(1) entrust(114027)
        //
        //    Algorithm(80) Composite(4) CompositeKey(1)
        public static readonly DerObjectIdentifier id_composite_key =
            new DerObjectIdentifier("2.16.840.1.114027.80.4.1");

        /// <summary>The object identifier <c>2.16.840.1.113894.746875.1.1</c>.</summary>
        public static readonly DerObjectIdentifier id_oracle_pkcs12_trusted_key_usage =
            new DerObjectIdentifier("2.16.840.1.113894.746875.1.1");
    }
}
