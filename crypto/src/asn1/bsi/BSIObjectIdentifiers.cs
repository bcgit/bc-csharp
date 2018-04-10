namespace Org.BouncyCastle.Asn1.Bsi
{
    public sealed class BsiObjectIdentifiers
    {
        /**
         * See https://www.bsi.bund.de/cae/servlet/contentblob/471398/publicationFile/30615/BSI-TR-03111_pdf.pdf
         * 
         * itu-t, ccitt(0) identified-organization(4) etsi(0) reserved(127) etsi-identified-organization(0) bsi-de(7)
         */
        public static readonly DerObjectIdentifier bsi_de = new DerObjectIdentifier("0.4.0.127.0.7");

        /* 0.4.0.127.0.7.1.1 Root identifier for elliptic curve cryptography */
        public static readonly DerObjectIdentifier id_ecc = bsi_de.Branch("1.1");

        /* 0.4.0.127.0.7.1.1.4.1 */
        public static readonly DerObjectIdentifier ecdsa_plain_signatures = id_ecc.Branch("4.1");
    
        /* 0.4.0.127.0.7.1.1.4.1.1 */
        public static readonly DerObjectIdentifier ecdsa_plain_SHA1 = ecdsa_plain_signatures.Branch("1");

        /* 0.4.0.127.0.7.1.1.4.1.2 */
        public static readonly DerObjectIdentifier ecdsa_plain_SHA224 = ecdsa_plain_signatures.Branch("2");

        /* 0.4.0.127.0.7.1.1.4.1.3 */
        public static readonly DerObjectIdentifier ecdsa_plain_SHA256 = ecdsa_plain_signatures.Branch("3");

        /* 0.4.0.127.0.7.1.1.4.1.4 */
        public static readonly DerObjectIdentifier ecdsa_plain_SHA384 = ecdsa_plain_signatures.Branch("4");

        /* 0.4.0.127.0.7.1.1.4.1.5 */
        public static readonly DerObjectIdentifier ecdsa_plain_SHA512 = ecdsa_plain_signatures.Branch("5");

        /* 0.4.0.127.0.7.1.1.4.1.6 */
        public static readonly DerObjectIdentifier ecdsa_plain_RIPEMD160 = ecdsa_plain_signatures.Branch("6");
    }
}
