using System;

namespace Org.BouncyCastle.Asn1.Eac
{
    /// <summary>Object identifiers for BSI TR-03110 extended access control.</summary>
    // TODO[api] Make static
    public abstract class EacObjectIdentifiers
    {
        /// <summary>The object identifier <c>0.4.0.127.0.7</c>.</summary>
        // bsi-de OBJECT IDENTIFIER ::= {
        //         itu-t(0) identified-organization(4) etsi(0)
        //         reserved(127) etsi-identified-organization(0) 7
        //     }
        public static readonly DerObjectIdentifier bsi_de = new DerObjectIdentifier("0.4.0.127.0.7");

        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.1</c>.</summary>
        // id-PK OBJECT IDENTIFIER ::= {
        //         bsi-de protocols(2) smartcard(2) 1
        //     }
        public static readonly DerObjectIdentifier id_PK = new DerObjectIdentifier(bsi_de + ".2.2.1");

        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.1.1</c>.</summary>
        public static readonly DerObjectIdentifier id_PK_DH = new DerObjectIdentifier(id_PK + ".1");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.1.2</c>.</summary>
        public static readonly DerObjectIdentifier id_PK_ECDH = new DerObjectIdentifier(id_PK + ".2");

        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.3</c>.</summary>
        // id-CA OBJECT IDENTIFIER ::= {
        //         bsi-de protocols(2) smartcard(2) 3
        //     }
        public static readonly DerObjectIdentifier id_CA = new DerObjectIdentifier(bsi_de + ".2.2.3");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.3.1</c>.</summary>
        public static readonly DerObjectIdentifier id_CA_DH = new DerObjectIdentifier(id_CA + ".1");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.3.1.1</c>.</summary>
        public static readonly DerObjectIdentifier id_CA_DH_3DES_CBC_CBC = new DerObjectIdentifier(id_CA_DH + ".1");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.3.2</c>.</summary>
        public static readonly DerObjectIdentifier id_CA_ECDH = new DerObjectIdentifier(id_CA + ".2");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.3.2.1</c>.</summary>
        public static readonly DerObjectIdentifier id_CA_ECDH_3DES_CBC_CBC = new DerObjectIdentifier(id_CA_ECDH + ".1");

        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2</c>.</summary>
        //
        // id-TA OBJECT IDENTIFIER ::= {
        //     bsi-de protocols(2) smartcard(2) 2
        // }
        public static readonly DerObjectIdentifier id_TA = new DerObjectIdentifier(bsi_de + ".2.2.2");

        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2.1</c>.</summary>
        public static readonly DerObjectIdentifier id_TA_RSA = new DerObjectIdentifier(id_TA + ".1");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2.1.1</c>.</summary>
        public static readonly DerObjectIdentifier id_TA_RSA_v1_5_SHA_1 = new DerObjectIdentifier(id_TA_RSA + ".1");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2.1.2</c>.</summary>
        public static readonly DerObjectIdentifier id_TA_RSA_v1_5_SHA_256 = new DerObjectIdentifier(id_TA_RSA + ".2");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2.1.3</c>.</summary>
        public static readonly DerObjectIdentifier id_TA_RSA_PSS_SHA_1 = new DerObjectIdentifier(id_TA_RSA + ".3");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2.1.4</c>.</summary>
        public static readonly DerObjectIdentifier id_TA_RSA_PSS_SHA_256 = new DerObjectIdentifier(id_TA_RSA + ".4");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2.2</c>.</summary>
        public static readonly DerObjectIdentifier id_TA_ECDSA = new DerObjectIdentifier(id_TA + ".2");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2.2.1</c>.</summary>
        public static readonly DerObjectIdentifier id_TA_ECDSA_SHA_1 = new DerObjectIdentifier(id_TA_ECDSA + ".1");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2.2.2</c>.</summary>
        public static readonly DerObjectIdentifier id_TA_ECDSA_SHA_224 = new DerObjectIdentifier(id_TA_ECDSA + ".2");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2.2.3</c>.</summary>
        public static readonly DerObjectIdentifier id_TA_ECDSA_SHA_256 = new DerObjectIdentifier(id_TA_ECDSA + ".3");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2.2.4</c>.</summary>
        public static readonly DerObjectIdentifier id_TA_ECDSA_SHA_384 = new DerObjectIdentifier(id_TA_ECDSA + ".4");
        /// <summary>The object identifier <c>0.4.0.127.0.7.2.2.2.2.5</c>.</summary>
        public static readonly DerObjectIdentifier id_TA_ECDSA_SHA_512 = new DerObjectIdentifier(id_TA_ECDSA + ".5");
    }
}
