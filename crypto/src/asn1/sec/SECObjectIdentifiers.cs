using Org.BouncyCastle.Asn1.X9;

namespace Org.BouncyCastle.Asn1.Sec
{
    // TODO[api] Make static
    public abstract class SecObjectIdentifiers
    {
        public static readonly DerObjectIdentifier certicom = new DerObjectIdentifier("1.3.132");

        public static readonly DerObjectIdentifier EllipticCurve = certicom.Branch("0");

        public static readonly DerObjectIdentifier SecT163k1 = new DerObjectIdentifier(EllipticCurve + ".1");
        public static readonly DerObjectIdentifier SecT163r1 = new DerObjectIdentifier(EllipticCurve + ".2");
        public static readonly DerObjectIdentifier SecT239k1 = new DerObjectIdentifier(EllipticCurve + ".3");
        public static readonly DerObjectIdentifier SecT113r1 = new DerObjectIdentifier(EllipticCurve + ".4");
        public static readonly DerObjectIdentifier SecT113r2 = new DerObjectIdentifier(EllipticCurve + ".5");
        public static readonly DerObjectIdentifier SecP112r1 = new DerObjectIdentifier(EllipticCurve + ".6");
        public static readonly DerObjectIdentifier SecP112r2 = new DerObjectIdentifier(EllipticCurve + ".7");
        public static readonly DerObjectIdentifier SecP160r1 = new DerObjectIdentifier(EllipticCurve + ".8");
        public static readonly DerObjectIdentifier SecP160k1 = new DerObjectIdentifier(EllipticCurve + ".9");
        public static readonly DerObjectIdentifier SecP256k1 = new DerObjectIdentifier(EllipticCurve + ".10");
        public static readonly DerObjectIdentifier SecT163r2 = new DerObjectIdentifier(EllipticCurve + ".15");
        public static readonly DerObjectIdentifier SecT283k1 = new DerObjectIdentifier(EllipticCurve + ".16");
        public static readonly DerObjectIdentifier SecT283r1 = new DerObjectIdentifier(EllipticCurve + ".17");
        public static readonly DerObjectIdentifier SecT131r1 = new DerObjectIdentifier(EllipticCurve + ".22");
        public static readonly DerObjectIdentifier SecT131r2 = new DerObjectIdentifier(EllipticCurve + ".23");
        public static readonly DerObjectIdentifier SecT193r1 = new DerObjectIdentifier(EllipticCurve + ".24");
        public static readonly DerObjectIdentifier SecT193r2 = new DerObjectIdentifier(EllipticCurve + ".25");
        public static readonly DerObjectIdentifier SecT233k1 = new DerObjectIdentifier(EllipticCurve + ".26");
        public static readonly DerObjectIdentifier SecT233r1 = new DerObjectIdentifier(EllipticCurve + ".27");
        public static readonly DerObjectIdentifier SecP128r1 = new DerObjectIdentifier(EllipticCurve + ".28");
        public static readonly DerObjectIdentifier SecP128r2 = new DerObjectIdentifier(EllipticCurve + ".29");
        public static readonly DerObjectIdentifier SecP160r2 = new DerObjectIdentifier(EllipticCurve + ".30");
        public static readonly DerObjectIdentifier SecP192k1 = new DerObjectIdentifier(EllipticCurve + ".31");
        public static readonly DerObjectIdentifier SecP224k1 = new DerObjectIdentifier(EllipticCurve + ".32");
        public static readonly DerObjectIdentifier SecP224r1 = new DerObjectIdentifier(EllipticCurve + ".33");
        public static readonly DerObjectIdentifier SecP384r1 = new DerObjectIdentifier(EllipticCurve + ".34");
        public static readonly DerObjectIdentifier SecP521r1 = new DerObjectIdentifier(EllipticCurve + ".35");
        public static readonly DerObjectIdentifier SecT409k1 = new DerObjectIdentifier(EllipticCurve + ".36");
        public static readonly DerObjectIdentifier SecT409r1 = new DerObjectIdentifier(EllipticCurve + ".37");
        public static readonly DerObjectIdentifier SecT571k1 = new DerObjectIdentifier(EllipticCurve + ".38");
        public static readonly DerObjectIdentifier SecT571r1 = new DerObjectIdentifier(EllipticCurve + ".39");

        public static readonly DerObjectIdentifier SecP192r1 = X9ObjectIdentifiers.Prime192v1;
        public static readonly DerObjectIdentifier SecP256r1 = X9ObjectIdentifiers.Prime256v1;

        public static readonly DerObjectIdentifier secg_scheme = certicom.Branch("1");

        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_recommendedKDF = secg_scheme.Branch("1");
        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_specifiedKDF = secg_scheme.Branch("2");
        public static readonly DerObjectIdentifier mqvSinglePass_recommendedKDF = secg_scheme.Branch("3");
        public static readonly DerObjectIdentifier mqvSinglePass_specifiedKDF = secg_scheme.Branch("4");
        public static readonly DerObjectIdentifier mqvFull_recommendedKDF = secg_scheme.Branch("5");
        public static readonly DerObjectIdentifier mqvFull_specifiedKDF = secg_scheme.Branch("6");
        public static readonly DerObjectIdentifier ecies_recommendedParameters = secg_scheme.Branch("7");
        public static readonly DerObjectIdentifier ecies_specifiedParameters = secg_scheme.Branch("8");

        public static readonly DerObjectIdentifier dhSinglePass_stdDH_kdf_schemes = secg_scheme.Branch("11");

        public static readonly DerObjectIdentifier dhSinglePass_stdDH_sha224kdf_scheme = dhSinglePass_stdDH_kdf_schemes.Branch("0");
        public static readonly DerObjectIdentifier dhSinglePass_stdDH_sha256kdf_scheme = dhSinglePass_stdDH_kdf_schemes.Branch("1");
        public static readonly DerObjectIdentifier dhSinglePass_stdDH_sha384kdf_scheme = dhSinglePass_stdDH_kdf_schemes.Branch("2");
        public static readonly DerObjectIdentifier dhSinglePass_stdDH_sha512kdf_scheme = dhSinglePass_stdDH_kdf_schemes.Branch("3");

        public static readonly DerObjectIdentifier ecdh = secg_scheme.Branch("12");
        public static readonly DerObjectIdentifier ecmqv = secg_scheme.Branch("13");

        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_kdf_schemes = secg_scheme.Branch("14");

        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_sha224kdf_scheme = dhSinglePass_cofactorDH_kdf_schemes.Branch("0");
        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_sha256kdf_scheme = dhSinglePass_cofactorDH_kdf_schemes.Branch("1");
        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_sha384kdf_scheme = dhSinglePass_cofactorDH_kdf_schemes.Branch("2");
        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_sha512kdf_scheme = dhSinglePass_cofactorDH_kdf_schemes.Branch("3");

        public static readonly DerObjectIdentifier mqvSinglePass_kdf_schemes = secg_scheme.Branch("15");

        public static readonly DerObjectIdentifier mqvSinglePass_sha224kdf_scheme = mqvSinglePass_kdf_schemes.Branch("0");
        public static readonly DerObjectIdentifier mqvSinglePass_sha256kdf_scheme = mqvSinglePass_kdf_schemes.Branch("1");
        public static readonly DerObjectIdentifier mqvSinglePass_sha384kdf_scheme = mqvSinglePass_kdf_schemes.Branch("2");
        public static readonly DerObjectIdentifier mqvSinglePass_sha512kdf_scheme = mqvSinglePass_kdf_schemes.Branch("3");

        public static readonly DerObjectIdentifier mqvFull_kdf_schemes = secg_scheme.Branch("16");

        public static readonly DerObjectIdentifier mqvFull_sha224kdf_scheme = mqvFull_kdf_schemes.Branch("0");
        public static readonly DerObjectIdentifier mqvFull_sha256kdf_scheme = mqvFull_kdf_schemes.Branch("1");
        public static readonly DerObjectIdentifier mqvFull_sha384kdf_scheme = mqvFull_kdf_schemes.Branch("2");
        public static readonly DerObjectIdentifier mqvFull_sha512kdf_scheme = mqvFull_kdf_schemes.Branch("3");

        public static readonly DerObjectIdentifier kdf_algorithms = secg_scheme.Branch("17");

        public static readonly DerObjectIdentifier x9_63_kdf = kdf_algorithms.Branch("0");
        public static readonly DerObjectIdentifier nist_concatenation_kdf = kdf_algorithms.Branch("1");
        public static readonly DerObjectIdentifier tls_kdf = kdf_algorithms.Branch("2");
        public static readonly DerObjectIdentifier ikev2_kdf = kdf_algorithms.Branch("3");
    }
}
