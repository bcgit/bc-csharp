using Org.BouncyCastle.Asn1.X9;

namespace Org.BouncyCastle.Asn1.Sec
{
    /// <summary>Object identifiers for SEC (Standards for Efficient Cryptography).</summary>
    // TODO[api] Make static
    public abstract class SecObjectIdentifiers
    {
        /// <summary>The object identifier <c>1.3.132</c>.</summary>
        public static readonly DerObjectIdentifier certicom = new DerObjectIdentifier("1.3.132");

        /// <summary>The object identifier <c>1.3.132.0</c>.</summary>
        public static readonly DerObjectIdentifier EllipticCurve = certicom.Branch("0");

        /// <summary>The object identifier <c>1.3.132.0.1</c>.</summary>
        public static readonly DerObjectIdentifier SecT163k1 = new DerObjectIdentifier(EllipticCurve + ".1");
        /// <summary>The object identifier <c>1.3.132.0.2</c>.</summary>
        public static readonly DerObjectIdentifier SecT163r1 = new DerObjectIdentifier(EllipticCurve + ".2");
        /// <summary>The object identifier <c>1.3.132.0.3</c>.</summary>
        public static readonly DerObjectIdentifier SecT239k1 = new DerObjectIdentifier(EllipticCurve + ".3");
        /// <summary>The object identifier <c>1.3.132.0.4</c>.</summary>
        public static readonly DerObjectIdentifier SecT113r1 = new DerObjectIdentifier(EllipticCurve + ".4");
        /// <summary>The object identifier <c>1.3.132.0.5</c>.</summary>
        public static readonly DerObjectIdentifier SecT113r2 = new DerObjectIdentifier(EllipticCurve + ".5");
        /// <summary>The object identifier <c>1.3.132.0.6</c>.</summary>
        public static readonly DerObjectIdentifier SecP112r1 = new DerObjectIdentifier(EllipticCurve + ".6");
        /// <summary>The object identifier <c>1.3.132.0.7</c>.</summary>
        public static readonly DerObjectIdentifier SecP112r2 = new DerObjectIdentifier(EllipticCurve + ".7");
        /// <summary>The object identifier <c>1.3.132.0.8</c>.</summary>
        public static readonly DerObjectIdentifier SecP160r1 = new DerObjectIdentifier(EllipticCurve + ".8");
        /// <summary>The object identifier <c>1.3.132.0.9</c>.</summary>
        public static readonly DerObjectIdentifier SecP160k1 = new DerObjectIdentifier(EllipticCurve + ".9");
        /// <summary>The object identifier <c>1.3.132.0.10</c>.</summary>
        public static readonly DerObjectIdentifier SecP256k1 = new DerObjectIdentifier(EllipticCurve + ".10");
        /// <summary>The object identifier <c>1.3.132.0.15</c>.</summary>
        public static readonly DerObjectIdentifier SecT163r2 = new DerObjectIdentifier(EllipticCurve + ".15");
        /// <summary>The object identifier <c>1.3.132.0.16</c>.</summary>
        public static readonly DerObjectIdentifier SecT283k1 = new DerObjectIdentifier(EllipticCurve + ".16");
        /// <summary>The object identifier <c>1.3.132.0.17</c>.</summary>
        public static readonly DerObjectIdentifier SecT283r1 = new DerObjectIdentifier(EllipticCurve + ".17");
        /// <summary>The object identifier <c>1.3.132.0.22</c>.</summary>
        public static readonly DerObjectIdentifier SecT131r1 = new DerObjectIdentifier(EllipticCurve + ".22");
        /// <summary>The object identifier <c>1.3.132.0.23</c>.</summary>
        public static readonly DerObjectIdentifier SecT131r2 = new DerObjectIdentifier(EllipticCurve + ".23");
        /// <summary>The object identifier <c>1.3.132.0.24</c>.</summary>
        public static readonly DerObjectIdentifier SecT193r1 = new DerObjectIdentifier(EllipticCurve + ".24");
        /// <summary>The object identifier <c>1.3.132.0.25</c>.</summary>
        public static readonly DerObjectIdentifier SecT193r2 = new DerObjectIdentifier(EllipticCurve + ".25");
        /// <summary>The object identifier <c>1.3.132.0.26</c>.</summary>
        public static readonly DerObjectIdentifier SecT233k1 = new DerObjectIdentifier(EllipticCurve + ".26");
        /// <summary>The object identifier <c>1.3.132.0.27</c>.</summary>
        public static readonly DerObjectIdentifier SecT233r1 = new DerObjectIdentifier(EllipticCurve + ".27");
        /// <summary>The object identifier <c>1.3.132.0.28</c>.</summary>
        public static readonly DerObjectIdentifier SecP128r1 = new DerObjectIdentifier(EllipticCurve + ".28");
        /// <summary>The object identifier <c>1.3.132.0.29</c>.</summary>
        public static readonly DerObjectIdentifier SecP128r2 = new DerObjectIdentifier(EllipticCurve + ".29");
        /// <summary>The object identifier <c>1.3.132.0.30</c>.</summary>
        public static readonly DerObjectIdentifier SecP160r2 = new DerObjectIdentifier(EllipticCurve + ".30");
        /// <summary>The object identifier <c>1.3.132.0.31</c>.</summary>
        public static readonly DerObjectIdentifier SecP192k1 = new DerObjectIdentifier(EllipticCurve + ".31");
        /// <summary>The object identifier <c>1.3.132.0.32</c>.</summary>
        public static readonly DerObjectIdentifier SecP224k1 = new DerObjectIdentifier(EllipticCurve + ".32");
        /// <summary>The object identifier <c>1.3.132.0.33</c>.</summary>
        public static readonly DerObjectIdentifier SecP224r1 = new DerObjectIdentifier(EllipticCurve + ".33");
        /// <summary>The object identifier <c>1.3.132.0.34</c>.</summary>
        public static readonly DerObjectIdentifier SecP384r1 = new DerObjectIdentifier(EllipticCurve + ".34");
        /// <summary>The object identifier <c>1.3.132.0.35</c>.</summary>
        public static readonly DerObjectIdentifier SecP521r1 = new DerObjectIdentifier(EllipticCurve + ".35");
        /// <summary>The object identifier <c>1.3.132.0.36</c>.</summary>
        public static readonly DerObjectIdentifier SecT409k1 = new DerObjectIdentifier(EllipticCurve + ".36");
        /// <summary>The object identifier <c>1.3.132.0.37</c>.</summary>
        public static readonly DerObjectIdentifier SecT409r1 = new DerObjectIdentifier(EllipticCurve + ".37");
        /// <summary>The object identifier <c>1.3.132.0.38</c>.</summary>
        public static readonly DerObjectIdentifier SecT571k1 = new DerObjectIdentifier(EllipticCurve + ".38");
        /// <summary>The object identifier <c>1.3.132.0.39</c>.</summary>
        public static readonly DerObjectIdentifier SecT571r1 = new DerObjectIdentifier(EllipticCurve + ".39");

        /// <summary>The object identifier <c>1.2.840.10045.3.1.1</c>.</summary>
        public static readonly DerObjectIdentifier SecP192r1 = X9ObjectIdentifiers.Prime192v1;
        /// <summary>The object identifier <c>1.2.840.10045.3.1.7</c>.</summary>
        public static readonly DerObjectIdentifier SecP256r1 = X9ObjectIdentifiers.Prime256v1;

        /// <summary>The object identifier <c>1.3.132.1</c>.</summary>
        public static readonly DerObjectIdentifier secg_scheme = certicom.Branch("1");

        /// <summary>The object identifier <c>1.3.132.1.1</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_recommendedKDF = secg_scheme.Branch("1");
        /// <summary>The object identifier <c>1.3.132.1.2</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_specifiedKDF = secg_scheme.Branch("2");
        /// <summary>The object identifier <c>1.3.132.1.3</c>.</summary>
        public static readonly DerObjectIdentifier mqvSinglePass_recommendedKDF = secg_scheme.Branch("3");
        /// <summary>The object identifier <c>1.3.132.1.4</c>.</summary>
        public static readonly DerObjectIdentifier mqvSinglePass_specifiedKDF = secg_scheme.Branch("4");
        /// <summary>The object identifier <c>1.3.132.1.5</c>.</summary>
        public static readonly DerObjectIdentifier mqvFull_recommendedKDF = secg_scheme.Branch("5");
        /// <summary>The object identifier <c>1.3.132.1.6</c>.</summary>
        public static readonly DerObjectIdentifier mqvFull_specifiedKDF = secg_scheme.Branch("6");
        /// <summary>The object identifier <c>1.3.132.1.7</c>.</summary>
        public static readonly DerObjectIdentifier ecies_recommendedParameters = secg_scheme.Branch("7");
        /// <summary>The object identifier <c>1.3.132.1.8</c>.</summary>
        public static readonly DerObjectIdentifier ecies_specifiedParameters = secg_scheme.Branch("8");

        /// <summary>The object identifier <c>1.3.132.1.11</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_stdDH_kdf_schemes = secg_scheme.Branch("11");

        /// <summary>The object identifier <c>1.3.132.1.11.0</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_stdDH_sha224kdf_scheme = dhSinglePass_stdDH_kdf_schemes.Branch("0");
        /// <summary>The object identifier <c>1.3.132.1.11.1</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_stdDH_sha256kdf_scheme = dhSinglePass_stdDH_kdf_schemes.Branch("1");
        /// <summary>The object identifier <c>1.3.132.1.11.2</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_stdDH_sha384kdf_scheme = dhSinglePass_stdDH_kdf_schemes.Branch("2");
        /// <summary>The object identifier <c>1.3.132.1.11.3</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_stdDH_sha512kdf_scheme = dhSinglePass_stdDH_kdf_schemes.Branch("3");

        /// <summary>The object identifier <c>1.3.132.1.12</c>.</summary>
        public static readonly DerObjectIdentifier ecdh = secg_scheme.Branch("12");
        /// <summary>The object identifier <c>1.3.132.1.13</c>.</summary>
        public static readonly DerObjectIdentifier ecmqv = secg_scheme.Branch("13");

        /// <summary>The object identifier <c>1.3.132.1.14</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_kdf_schemes = secg_scheme.Branch("14");

        /// <summary>The object identifier <c>1.3.132.1.14.0</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_sha224kdf_scheme = dhSinglePass_cofactorDH_kdf_schemes.Branch("0");
        /// <summary>The object identifier <c>1.3.132.1.14.1</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_sha256kdf_scheme = dhSinglePass_cofactorDH_kdf_schemes.Branch("1");
        /// <summary>The object identifier <c>1.3.132.1.14.2</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_sha384kdf_scheme = dhSinglePass_cofactorDH_kdf_schemes.Branch("2");
        /// <summary>The object identifier <c>1.3.132.1.14.3</c>.</summary>
        public static readonly DerObjectIdentifier dhSinglePass_cofactorDH_sha512kdf_scheme = dhSinglePass_cofactorDH_kdf_schemes.Branch("3");

        /// <summary>The object identifier <c>1.3.132.1.15</c>.</summary>
        public static readonly DerObjectIdentifier mqvSinglePass_kdf_schemes = secg_scheme.Branch("15");

        /// <summary>The object identifier <c>1.3.132.1.15.0</c>.</summary>
        public static readonly DerObjectIdentifier mqvSinglePass_sha224kdf_scheme = mqvSinglePass_kdf_schemes.Branch("0");
        /// <summary>The object identifier <c>1.3.132.1.15.1</c>.</summary>
        public static readonly DerObjectIdentifier mqvSinglePass_sha256kdf_scheme = mqvSinglePass_kdf_schemes.Branch("1");
        /// <summary>The object identifier <c>1.3.132.1.15.2</c>.</summary>
        public static readonly DerObjectIdentifier mqvSinglePass_sha384kdf_scheme = mqvSinglePass_kdf_schemes.Branch("2");
        /// <summary>The object identifier <c>1.3.132.1.15.3</c>.</summary>
        public static readonly DerObjectIdentifier mqvSinglePass_sha512kdf_scheme = mqvSinglePass_kdf_schemes.Branch("3");

        /// <summary>The object identifier <c>1.3.132.1.16</c>.</summary>
        public static readonly DerObjectIdentifier mqvFull_kdf_schemes = secg_scheme.Branch("16");

        /// <summary>The object identifier <c>1.3.132.1.16.0</c>.</summary>
        public static readonly DerObjectIdentifier mqvFull_sha224kdf_scheme = mqvFull_kdf_schemes.Branch("0");
        /// <summary>The object identifier <c>1.3.132.1.16.1</c>.</summary>
        public static readonly DerObjectIdentifier mqvFull_sha256kdf_scheme = mqvFull_kdf_schemes.Branch("1");
        /// <summary>The object identifier <c>1.3.132.1.16.2</c>.</summary>
        public static readonly DerObjectIdentifier mqvFull_sha384kdf_scheme = mqvFull_kdf_schemes.Branch("2");
        /// <summary>The object identifier <c>1.3.132.1.16.3</c>.</summary>
        public static readonly DerObjectIdentifier mqvFull_sha512kdf_scheme = mqvFull_kdf_schemes.Branch("3");

        /// <summary>The object identifier <c>1.3.132.1.17</c>.</summary>
        public static readonly DerObjectIdentifier kdf_algorithms = secg_scheme.Branch("17");

        /// <summary>The object identifier <c>1.3.132.1.17.0</c>.</summary>
        public static readonly DerObjectIdentifier x9_63_kdf = kdf_algorithms.Branch("0");
        /// <summary>The object identifier <c>1.3.132.1.17.1</c>.</summary>
        public static readonly DerObjectIdentifier nist_concatenation_kdf = kdf_algorithms.Branch("1");
        /// <summary>The object identifier <c>1.3.132.1.17.2</c>.</summary>
        public static readonly DerObjectIdentifier tls_kdf = kdf_algorithms.Branch("2");
        /// <summary>The object identifier <c>1.3.132.1.17.3</c>.</summary>
        public static readonly DerObjectIdentifier ikev2_kdf = kdf_algorithms.Branch("3");
    }
}
