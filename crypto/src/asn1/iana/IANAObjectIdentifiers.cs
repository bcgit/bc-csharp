namespace Org.BouncyCastle.Asn1.Iana
{
    // TODO[api] Make static
    public abstract class IanaObjectIdentifiers
    {
        /** { iso(1) identifier-organization(3) dod(6) internet(1) } == IETF defined things */
        public static readonly DerObjectIdentifier internet = new DerObjectIdentifier("1.3.6.1");
        /** 1.3.6.1.1: Internet directory: X.500 */
        public static readonly DerObjectIdentifier directory = internet.Branch("1");
        /** 1.3.6.1.2: Internet management */
        public static readonly DerObjectIdentifier mgmt = internet.Branch("2");
        /** 1.3.6.1.3: */
        public static readonly DerObjectIdentifier experimental = internet.Branch("3");
        /** 1.3.6.1.4: */
        public static readonly DerObjectIdentifier cls_private = internet.Branch("4");
        /** 1.3.6.1.5: Security services */
        public static readonly DerObjectIdentifier security = internet.Branch("5");
        /** 1.3.6.1.6: SNMPv2 -- never really used */
        public static readonly DerObjectIdentifier SNMPv2 = internet.Branch("6");
        /** 1.3.6.1.7: mail -- never really used */
        public static readonly DerObjectIdentifier mail = internet.Branch("7");

        // id-SHA1 OBJECT IDENTIFIER ::=
        // {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) ipsec(8) isakmpOakley(1)}
        //

        /** IANA security mechanisms; 1.3.6.1.5.5 */
        public static readonly DerObjectIdentifier security_mechanisms = security.Branch("5");
        /** IANA security nametypes;  1.3.6.1.5.6 */
        public static readonly DerObjectIdentifier security_nametypes = security.Branch("6");

        /** PKIX base OID:            1.3.6.1.5.5.7 */
        public static readonly DerObjectIdentifier pkix = security_mechanisms.Branch("7");

        /** IPSEC base OID:                        1.3.6.1.5.5.8 */
        public static readonly DerObjectIdentifier ipsec = security_mechanisms.Branch("8");
        /** IPSEC ISAKMP-Oakley OID:               1.3.6.1.5.5.8.1 */
        public static readonly DerObjectIdentifier IsakmpOakley = ipsec.Branch("1");

        /** IPSEC ISAKMP-Oakley hmacMD5 OID:       1.3.6.1.5.5.8.1.1 */
        public static readonly DerObjectIdentifier HmacMD5 = IsakmpOakley.Branch("1");
        /** IPSEC ISAKMP-Oakley hmacSHA1 OID:      1.3.6.1.5.5.8.1.2 */
        public static readonly DerObjectIdentifier HmacSha1 = IsakmpOakley.Branch("2");

        /** IPSEC ISAKMP-Oakley hmacTIGER OID:     1.3.6.1.5.5.8.1.3 */
        public static readonly DerObjectIdentifier HmacTiger = IsakmpOakley.Branch("3");

        /** IPSEC ISAKMP-Oakley hmacRIPEMD160 OID: 1.3.6.1.5.5.8.1.4 */
        public static readonly DerObjectIdentifier HmacRipeMD160 = IsakmpOakley.Branch("4");
    }
}
