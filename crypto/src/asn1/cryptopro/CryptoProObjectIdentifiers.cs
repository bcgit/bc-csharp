using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Asn1.CryptoPro
{
    public abstract class CryptoProObjectIdentifiers
    {
        // GOST Algorithms OBJECT IDENTIFIERS :
        // { iso(1) member-body(2) ru(643) rans(2) cryptopro(2)}
        [Obsolete("Use GOST_id instead")]
        public const string GostID = "1.2.643.2.2";
        public static readonly DerObjectIdentifier GOST_id = new DerObjectIdentifier("1.2.643.2.2");

        public static readonly DerObjectIdentifier GostR3411 = GOST_id.Branch("9");
        public static readonly DerObjectIdentifier GostR3411Hmac = GOST_id.Branch("10");

        public static readonly DerObjectIdentifier id_Gost28147_89_None_KeyWrap = GOST_id.Branch("13.0");
        public static readonly DerObjectIdentifier id_Gost28147_89_CryptoPro_KeyWrap =  GOST_id.Branch("13.1");

        public static readonly DerObjectIdentifier GostR28147Gcfb = GOST_id.Branch("21");
        [Obsolete("Use 'GostR28147Gcfb' instead")]
        public static readonly DerObjectIdentifier GostR28147Cbc = GostR28147Gcfb;

        public static readonly DerObjectIdentifier ID_Gost28147_89_CryptoPro_TestParamSet = GOST_id.Branch("31.0");
        public static readonly DerObjectIdentifier ID_Gost28147_89_CryptoPro_A_ParamSet = GOST_id.Branch("31.1");
        public static readonly DerObjectIdentifier ID_Gost28147_89_CryptoPro_B_ParamSet = GOST_id.Branch("31.2");
        public static readonly DerObjectIdentifier ID_Gost28147_89_CryptoPro_C_ParamSet = GOST_id.Branch("31.3");
        public static readonly DerObjectIdentifier ID_Gost28147_89_CryptoPro_D_ParamSet = GOST_id.Branch("31.4");

        public static readonly DerObjectIdentifier GostR3410x94 = GOST_id.Branch("20");
        public static readonly DerObjectIdentifier GostR3410x2001 = GOST_id.Branch("19");

        public static readonly DerObjectIdentifier GostR3411x94WithGostR3410x94 = GOST_id.Branch("4");
        public static readonly DerObjectIdentifier GostR3411x94WithGostR3410x2001 = GOST_id.Branch("3");

		// { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) hashes(30) }
        public static readonly DerObjectIdentifier GostR3411x94CryptoProParamSet = GOST_id.Branch("30.1");

		// { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) signs(32) }
        public static readonly DerObjectIdentifier GostR3410x94CryptoProA = GOST_id.Branch("32.2");
        public static readonly DerObjectIdentifier GostR3410x94CryptoProB = GOST_id.Branch("32.3");
        public static readonly DerObjectIdentifier GostR3410x94CryptoProC = GOST_id.Branch("32.4");
        public static readonly DerObjectIdentifier GostR3410x94CryptoProD = GOST_id.Branch("32.5");

		// { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) exchanges(33) }
        public static readonly DerObjectIdentifier GostR3410x94CryptoProXchA = GOST_id.Branch("33.1");
        public static readonly DerObjectIdentifier GostR3410x94CryptoProXchB = GOST_id.Branch("33.2");
        public static readonly DerObjectIdentifier GostR3410x94CryptoProXchC = GOST_id.Branch("33.3");

		//{ iso(1) member-body(2)ru(643) rans(2) cryptopro(2) ecc-signs(35) }
        public static readonly DerObjectIdentifier GostR3410x2001CryptoProA = GOST_id.Branch("35.1");
        public static readonly DerObjectIdentifier GostR3410x2001CryptoProB = GOST_id.Branch("35.2");
        public static readonly DerObjectIdentifier GostR3410x2001CryptoProC = GOST_id.Branch("35.3");

		// { iso(1) member-body(2) ru(643) rans(2) cryptopro(2) ecc-exchanges(36) }
        public static readonly DerObjectIdentifier GostR3410x2001CryptoProXchA = GOST_id.Branch("36.0");
        public static readonly DerObjectIdentifier GostR3410x2001CryptoProXchB = GOST_id.Branch("36.1");

        public static readonly DerObjectIdentifier GostR3410x2001CryptoProESDH = GOST_id.Branch("96");

        public static readonly DerObjectIdentifier GostR3410x2001DH = GOST_id.Branch("98");
    }
}
