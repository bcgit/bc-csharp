using System;

namespace Org.BouncyCastle.Asn1.X9
{
    /// <summary>Object identifiers for ANSI X9.</summary>
    // TODO[api] Make static
    public abstract class X9ObjectIdentifiers
    {
        //
        // X9.62
        //
        // ansi-X9-62 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
        //            us(840) ansi-x962(10045) }
        //

        /// <summary>The object identifier <c>1.2.840.10045</c>.</summary>
        public static readonly DerObjectIdentifier ansi_X9_62 = new DerObjectIdentifier("1.2.840.10045");

        /// <summary>The object identifier <c>1.2.840.10045.1</c>.</summary>
        public static readonly DerObjectIdentifier IdFieldType = ansi_X9_62.Branch("1");

        /// <summary>The object identifier <c>1.2.840.10045.1.1</c>.</summary>
        public static readonly DerObjectIdentifier PrimeField = IdFieldType.Branch("1");
        /// <summary>The object identifier <c>1.2.840.10045.1.2</c>.</summary>
        public static readonly DerObjectIdentifier CharacteristicTwoField = IdFieldType.Branch("2");

        /// <summary>The object identifier <c>1.2.840.10045.1.2.3.1</c>.</summary>
        public static readonly DerObjectIdentifier GNBasis = CharacteristicTwoField.Branch("3.1");
        /// <summary>The object identifier <c>1.2.840.10045.1.2.3.2</c>.</summary>
        public static readonly DerObjectIdentifier TPBasis = CharacteristicTwoField.Branch("3.2");
        /// <summary>The object identifier <c>1.2.840.10045.1.2.3.3</c>.</summary>
        public static readonly DerObjectIdentifier PPBasis = CharacteristicTwoField.Branch("3.3");

        /// <summary>The object identifier <c>1.2.840.10045.4</c>.</summary>
        public static readonly DerObjectIdentifier id_ecSigType = ansi_X9_62.Branch("4");

        /// <summary>The object identifier <c>1.2.840.10045.4.1</c>.</summary>
        public static readonly DerObjectIdentifier ECDsaWithSha1 = id_ecSigType.Branch("1");

        /// <summary>The object identifier <c>1.2.840.10045.2</c>.</summary>
        public static readonly DerObjectIdentifier id_publicKeyType = ansi_X9_62.Branch("2");

        /// <summary>The object identifier <c>1.2.840.10045.2.1</c>.</summary>
        public static readonly DerObjectIdentifier IdECPublicKey = id_publicKeyType.Branch("1");

        /// <summary>The object identifier <c>1.2.840.10045.4.3</c>.</summary>
        public static readonly DerObjectIdentifier ECDsaWithSha2 = id_ecSigType.Branch("3");

        /// <summary>The object identifier <c>1.2.840.10045.4.3.1</c>.</summary>
        public static readonly DerObjectIdentifier ECDsaWithSha224 = ECDsaWithSha2.Branch("1");
        /// <summary>The object identifier <c>1.2.840.10045.4.3.2</c>.</summary>
        public static readonly DerObjectIdentifier ECDsaWithSha256 = ECDsaWithSha2.Branch("2");
        /// <summary>The object identifier <c>1.2.840.10045.4.3.3</c>.</summary>
        public static readonly DerObjectIdentifier ECDsaWithSha384 = ECDsaWithSha2.Branch("3");
        /// <summary>The object identifier <c>1.2.840.10045.4.3.4</c>.</summary>
        public static readonly DerObjectIdentifier ECDsaWithSha512 = ECDsaWithSha2.Branch("4");


        /// <summary>The object identifier <c>1.2.840.10045.3</c>.</summary>
        //
        // named curves
        //
        public static readonly DerObjectIdentifier EllipticCurve = ansi_X9_62.Branch("3");

        /// <summary>The object identifier <c>1.2.840.10045.3.0</c>.</summary>
        //
        // Two Curves
        //
        public static readonly DerObjectIdentifier CTwoCurve = EllipticCurve.Branch("0");

        /// <summary>The object identifier <c>1.2.840.10045.3.0.1</c>.</summary>
        public static readonly DerObjectIdentifier C2Pnb163v1 = CTwoCurve.Branch("1");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.2</c>.</summary>
        public static readonly DerObjectIdentifier C2Pnb163v2 = CTwoCurve.Branch("2");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.3</c>.</summary>
        public static readonly DerObjectIdentifier C2Pnb163v3 = CTwoCurve.Branch("3");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.4</c>.</summary>
        public static readonly DerObjectIdentifier C2Pnb176w1 = CTwoCurve.Branch("4");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.5</c>.</summary>
        public static readonly DerObjectIdentifier C2Tnb191v1 = CTwoCurve.Branch("5");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.6</c>.</summary>
        public static readonly DerObjectIdentifier C2Tnb191v2 = CTwoCurve.Branch("6");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.7</c>.</summary>
        public static readonly DerObjectIdentifier C2Tnb191v3 = CTwoCurve.Branch("7");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.8</c>.</summary>
        public static readonly DerObjectIdentifier C2Onb191v4 = CTwoCurve.Branch("8");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.9</c>.</summary>
        public static readonly DerObjectIdentifier C2Onb191v5 = CTwoCurve.Branch("9");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.10</c>.</summary>
        public static readonly DerObjectIdentifier C2Pnb208w1 = CTwoCurve.Branch("10");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.11</c>.</summary>
        public static readonly DerObjectIdentifier C2Tnb239v1 = CTwoCurve.Branch("11");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.12</c>.</summary>
        public static readonly DerObjectIdentifier C2Tnb239v2 = CTwoCurve.Branch("12");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.13</c>.</summary>
        public static readonly DerObjectIdentifier C2Tnb239v3 = CTwoCurve.Branch("13");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.14</c>.</summary>
        public static readonly DerObjectIdentifier C2Onb239v4 = CTwoCurve.Branch("14");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.15</c>.</summary>
        public static readonly DerObjectIdentifier C2Onb239v5 = CTwoCurve.Branch("15");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.16</c>.</summary>
        public static readonly DerObjectIdentifier C2Pnb272w1 = CTwoCurve.Branch("16");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.17</c>.</summary>
        public static readonly DerObjectIdentifier C2Pnb304w1 = CTwoCurve.Branch("17");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.18</c>.</summary>
        public static readonly DerObjectIdentifier C2Tnb359v1 = CTwoCurve.Branch("18");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.19</c>.</summary>
        public static readonly DerObjectIdentifier C2Pnb368w1 = CTwoCurve.Branch("19");
        /// <summary>The object identifier <c>1.2.840.10045.3.0.20</c>.</summary>
        public static readonly DerObjectIdentifier C2Tnb431r1 = CTwoCurve.Branch("20");

        /// <summary>The object identifier <c>1.2.840.10045.3.1</c>.</summary>
        //
        // Prime
        //
        public static readonly DerObjectIdentifier PrimeCurve = EllipticCurve.Branch("1");

        /// <summary>The object identifier <c>1.2.840.10045.3.1.1</c>.</summary>
        public static readonly DerObjectIdentifier Prime192v1 = PrimeCurve.Branch("1");
        /// <summary>The object identifier <c>1.2.840.10045.3.1.2</c>.</summary>
        public static readonly DerObjectIdentifier Prime192v2 = PrimeCurve.Branch("2");
        /// <summary>The object identifier <c>1.2.840.10045.3.1.3</c>.</summary>
        public static readonly DerObjectIdentifier Prime192v3 = PrimeCurve.Branch("3");
        /// <summary>The object identifier <c>1.2.840.10045.3.1.4</c>.</summary>
        public static readonly DerObjectIdentifier Prime239v1 = PrimeCurve.Branch("4");
        /// <summary>The object identifier <c>1.2.840.10045.3.1.5</c>.</summary>
        public static readonly DerObjectIdentifier Prime239v2 = PrimeCurve.Branch("5");
        /// <summary>The object identifier <c>1.2.840.10045.3.1.6</c>.</summary>
        public static readonly DerObjectIdentifier Prime239v3 = PrimeCurve.Branch("6");
        /// <summary>The object identifier <c>1.2.840.10045.3.1.7</c>.</summary>
        public static readonly DerObjectIdentifier Prime256v1 = PrimeCurve.Branch("7");

        /// <summary>The object identifier <c>1.2.840.10040.4.1</c>.</summary>
        //
        // DSA
        //
        // dsapublicnumber OBJECT IDENTIFIER ::= { iso(1) member-body(2)
        //            us(840) ansi-x957(10040) number-type(4) 1 }
        public static readonly DerObjectIdentifier IdDsa = new DerObjectIdentifier("1.2.840.10040.4.1");

        /**
         *   id-dsa-with-sha1 OBJECT IDENTIFIER ::=  { iso(1) member-body(2)
         *         us(840) x9-57 (10040) x9cm(4) 3 }
         */
        public static readonly DerObjectIdentifier IdDsaWithSha1 = new DerObjectIdentifier("1.2.840.10040.4.3");

        /**
         * X9.63
         */
        // TODO Seems this ought to be be 1.3.133.16.840.9.63.0, but may be in common use
        public static readonly DerObjectIdentifier X9x63Scheme = new DerObjectIdentifier("1.3.133.16.840.63.0");
        /// <summary>The object identifier <c>1.3.133.16.840.63.0.2</c>.</summary>
        public static readonly DerObjectIdentifier DHSinglePassStdDHSha1KdfScheme = X9x63Scheme.Branch("2");
        /// <summary>The object identifier <c>1.3.133.16.840.63.0.3</c>.</summary>
        public static readonly DerObjectIdentifier DHSinglePassCofactorDHSha1KdfScheme = X9x63Scheme.Branch("3");
        /// <summary>The object identifier <c>1.3.133.16.840.63.0.16</c>.</summary>
        public static readonly DerObjectIdentifier MqvSinglePassSha1KdfScheme = X9x63Scheme.Branch("16");

        /**
         * X9.42
         */

        /// <summary>The object identifier <c>1.2.840.10046</c>.</summary>
        public static readonly DerObjectIdentifier ansi_x9_42 = new DerObjectIdentifier("1.2.840.10046");

        /// <summary>The object identifier <c>1.2.840.10046.2.1</c>.</summary>
        //
        // Diffie-Hellman
        //
        // dhpublicnumber OBJECT IDENTIFIER ::= { iso(1) member-body(2)
        //            us(840) ansi-x942(10046) number-type(2) 1 }
        //
        public static readonly DerObjectIdentifier DHPublicNumber = ansi_x9_42.Branch("2.1");

        /// <summary>The object identifier <c>1.2.840.10046.2.3</c>.</summary>
        public static readonly DerObjectIdentifier X9x42Schemes = ansi_x9_42.Branch("2.3");

        /// <summary>The object identifier <c>1.2.840.10046.2.3.1</c>.</summary>
        public static readonly DerObjectIdentifier DHStatic = X9x42Schemes.Branch("1");
        /// <summary>The object identifier <c>1.2.840.10046.2.3.2</c>.</summary>
        public static readonly DerObjectIdentifier DHEphem = X9x42Schemes.Branch("2");
        /// <summary>The object identifier <c>1.2.840.10046.2.3.3</c>.</summary>
        public static readonly DerObjectIdentifier DHOneFlow = X9x42Schemes.Branch("3");
        /// <summary>The object identifier <c>1.2.840.10046.2.3.4</c>.</summary>
        public static readonly DerObjectIdentifier DHHybrid1 = X9x42Schemes.Branch("4");
        /// <summary>The object identifier <c>1.2.840.10046.2.3.5</c>.</summary>
        public static readonly DerObjectIdentifier DHHybrid2 = X9x42Schemes.Branch("5");
        /// <summary>The object identifier <c>1.2.840.10046.2.3.6</c>.</summary>
        public static readonly DerObjectIdentifier DHHybridOneFlow = X9x42Schemes.Branch("6");
        /// <summary>The object identifier <c>1.2.840.10046.2.3.7</c>.</summary>
        public static readonly DerObjectIdentifier Mqv2 = X9x42Schemes.Branch("7");
        /// <summary>The object identifier <c>1.2.840.10046.2.3.8</c>.</summary>
        public static readonly DerObjectIdentifier Mqv1 = X9x42Schemes.Branch("8");
    }
}
