using System;

namespace Org.BouncyCastle.Asn1.CryptoPro
{
    /// <summary>Object identifiers for CryptoPro.</summary>
    // TODO[api] Make static
    public abstract class CryptoProObjectIdentifiers
    {
        /// <summary>The <c>GostID</c> constant, with the value <c>1.2.643.2.2</c>.</summary>
        // GOST Algorithms OBJECT IDENTIFIERS :
        // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2)}
        [Obsolete("Use GOST_id instead")]
        public const string GostID = "1.2.643.2.2";
        /// <summary>The object identifier <c>1.2.643.2.2</c>.</summary>
        public static readonly DerObjectIdentifier GOST_id = new DerObjectIdentifier("1.2.643.2.2");

        /// <summary>The object identifier <c>1.2.643.2.2.9</c>.</summary>
        public static readonly DerObjectIdentifier GostR3411 = GOST_id.Branch("9");
        /// <summary>The object identifier <c>1.2.643.2.2.10</c>.</summary>
        public static readonly DerObjectIdentifier GostR3411Hmac = GOST_id.Branch("10");

        /// <summary>The object identifier <c>1.2.643.2.2.13.0</c>.</summary>
        public static readonly DerObjectIdentifier id_Gost28147_89_None_KeyWrap = GOST_id.Branch("13.0");
        /// <summary>The object identifier <c>1.2.643.2.2.13.1</c>.</summary>
        public static readonly DerObjectIdentifier id_Gost28147_89_CryptoPro_KeyWrap =  GOST_id.Branch("13.1");

        /// <summary>The object identifier <c>1.2.643.2.2.21</c>.</summary>
        public static readonly DerObjectIdentifier GostR28147Gcfb = GOST_id.Branch("21");
        /// <summary>The object identifier <c>1.2.643.2.2.21</c>.</summary>
        [Obsolete("Use 'GostR28147Gcfb' instead")]
        public static readonly DerObjectIdentifier GostR28147Cbc = GostR28147Gcfb;

        /// <summary>The object identifier <c>1.2.643.2.2.31.0</c>.</summary>
        public static readonly DerObjectIdentifier ID_Gost28147_89_CryptoPro_TestParamSet = GOST_id.Branch("31.0");
        /// <summary>The object identifier <c>1.2.643.2.2.31.1</c>.</summary>
        public static readonly DerObjectIdentifier ID_Gost28147_89_CryptoPro_A_ParamSet = GOST_id.Branch("31.1");
        /// <summary>The object identifier <c>1.2.643.2.2.31.2</c>.</summary>
        public static readonly DerObjectIdentifier ID_Gost28147_89_CryptoPro_B_ParamSet = GOST_id.Branch("31.2");
        /// <summary>The object identifier <c>1.2.643.2.2.31.3</c>.</summary>
        public static readonly DerObjectIdentifier ID_Gost28147_89_CryptoPro_C_ParamSet = GOST_id.Branch("31.3");
        /// <summary>The object identifier <c>1.2.643.2.2.31.4</c>.</summary>
        public static readonly DerObjectIdentifier ID_Gost28147_89_CryptoPro_D_ParamSet = GOST_id.Branch("31.4");

        /// <summary>The object identifier <c>1.2.643.2.2.20</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x94 = GOST_id.Branch("20");
        /// <summary>The object identifier <c>1.2.643.2.2.19</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x2001 = GOST_id.Branch("19");

        /// <summary>The object identifier <c>1.2.643.2.2.4</c>.</summary>
        public static readonly DerObjectIdentifier GostR3411x94WithGostR3410x94 = GOST_id.Branch("4");
        /// <summary>The object identifier <c>1.2.643.2.2.3</c>.</summary>
        public static readonly DerObjectIdentifier GostR3411x94WithGostR3410x2001 = GOST_id.Branch("3");

        // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) hashes(30) }
        public static readonly DerObjectIdentifier GostR3411x94TestParamSet = GOST_id.Branch("30.0");
        /// <summary>The object identifier <c>1.2.643.2.2.30.1</c>.</summary>
        // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) hashes(30) }
        public static readonly DerObjectIdentifier GostR3411x94CryptoProParamSet = GOST_id.Branch("30.1");

        /// <summary>The object identifier <c>1.2.643.2.2.32.2</c>.</summary>
        // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) signs(32) }
        public static readonly DerObjectIdentifier GostR3410x94CryptoProA = GOST_id.Branch("32.2");
        /// <summary>The object identifier <c>1.2.643.2.2.32.3</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x94CryptoProB = GOST_id.Branch("32.3");
        /// <summary>The object identifier <c>1.2.643.2.2.32.4</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x94CryptoProC = GOST_id.Branch("32.4");
        /// <summary>The object identifier <c>1.2.643.2.2.32.5</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x94CryptoProD = GOST_id.Branch("32.5");

        /// <summary>The object identifier <c>1.2.643.2.2.33.1</c>.</summary>
        // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) exchanges(33) }
        public static readonly DerObjectIdentifier GostR3410x94CryptoProXchA = GOST_id.Branch("33.1");
        /// <summary>The object identifier <c>1.2.643.2.2.33.2</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x94CryptoProXchB = GOST_id.Branch("33.2");
        /// <summary>The object identifier <c>1.2.643.2.2.33.3</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x94CryptoProXchC = GOST_id.Branch("33.3");

        /// <summary>The object identifier <c>1.2.643.2.2.35.1</c>.</summary>
        //{ iso(1) member-body(2)ru(643) rans(2) cryptopro(2) ecc-signs(35) }
        public static readonly DerObjectIdentifier GostR3410x2001CryptoProA = GOST_id.Branch("35.1");
        /// <summary>The object identifier <c>1.2.643.2.2.35.2</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x2001CryptoProB = GOST_id.Branch("35.2");
        /// <summary>The object identifier <c>1.2.643.2.2.35.3</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x2001CryptoProC = GOST_id.Branch("35.3");

        /// <summary>The object identifier <c>1.2.643.2.2.36.0</c>.</summary>
        // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) ecc-exchanges(36) }
        public static readonly DerObjectIdentifier GostR3410x2001CryptoProXchA = GOST_id.Branch("36.0");
        /// <summary>The object identifier <c>1.2.643.2.2.36.1</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x2001CryptoProXchB = GOST_id.Branch("36.1");

        /// <summary>The object identifier <c>1.2.643.2.2.36.0</c>.</summary>
        [Obsolete("Erroneous; will be removed")]
        public static readonly DerObjectIdentifier GostElSgDH3410Default = GOST_id.Branch("36.0");
        /// <summary>The object identifier <c>1.2.643.2.2.36.1</c>.</summary>
        [Obsolete("Erroneous; will be removed")]
        public static readonly DerObjectIdentifier GostElSgDH3410x1 = GOST_id.Branch("36.1");

        /// <summary>The object identifier <c>1.2.643.2.2.96</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x2001CryptoProESDH = GOST_id.Branch("96");

        /// <summary>The object identifier <c>1.2.643.2.2.98</c>.</summary>
        public static readonly DerObjectIdentifier GostR3410x2001DH = GOST_id.Branch("98");
    }
}
