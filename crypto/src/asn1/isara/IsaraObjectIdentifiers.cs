using System;

namespace Org.BouncyCastle.Asn1.Isara
{
    public static class IsaraObjectIdentifiers
    {
        /*
        id-alg-xmss  OBJECT IDENTIFIER ::= { itu-t(0)
                 identified-organization(4) etsi(0) reserved(127)
                 etsi-identified-organization(0) isara(15) algorithms(1)
                 asymmetric(1) xmss(13) 0 }
         */
        public static readonly DerObjectIdentifier id_alg_xmss = new DerObjectIdentifier("0.4.0.127.0.15.1.1.13.0");

        /*
          id-alg-xmssmt  OBJECT IDENTIFIER ::= { itu-t(0)
             identified-organization(4) etsi(0) reserved(127)
             etsi-identified-organization(0) isara(15) algorithms(1)
             asymmetric(1) xmssmt(14) 0 }
         */
        public static readonly DerObjectIdentifier id_alg_xmssmt = new DerObjectIdentifier("0.4.0.127.0.15.1.1.14.0");
    }
}
