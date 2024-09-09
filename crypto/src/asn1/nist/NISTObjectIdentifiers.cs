using System;

namespace Org.BouncyCastle.Asn1.Nist
{
    // TODO[api] Make static
    public sealed class NistObjectIdentifiers
    {
        private NistObjectIdentifiers()
        {
        }

        //
        // NIST
        //     iso/itu(2) joint-assign(16) us(840) organization(1) gov(101) csor(3)

        //
        // nistalgorithms(4)
        //
        /// <summary> 2.16.840.1.101.3.4 -- algorithms </summary>
        public static readonly DerObjectIdentifier NistAlgorithm = new DerObjectIdentifier("2.16.840.1.101.3.4");
        /// <summary> 2.16.840.1.101.3.4.2 </summary>
        public static readonly DerObjectIdentifier HashAlgs = NistAlgorithm.Branch("2");
        /// <summary> 2.16.840.1.101.3.4.2.1 </summary>
        public static readonly DerObjectIdentifier IdSha256 = HashAlgs.Branch("1");
        /// <summary> 2.16.840.1.101.3.4.2.2 </summary>
        public static readonly DerObjectIdentifier IdSha384 = HashAlgs.Branch("2");
        /// <summary> 2.16.840.1.101.3.4.2.3 </summary>
        public static readonly DerObjectIdentifier IdSha512 = HashAlgs.Branch("3");
        /// <summary> 2.16.840.1.101.3.4.2.4 </summary>
        public static readonly DerObjectIdentifier IdSha224 = HashAlgs.Branch("4");
        /// <summary> 2.16.840.1.101.3.4.2.5 </summary>
        public static readonly DerObjectIdentifier IdSha512_224 = HashAlgs.Branch("5");
        /// <summary> 2.16.840.1.101.3.4.2.6 </summary>
        public static readonly DerObjectIdentifier IdSha512_256 = HashAlgs.Branch("6");
        /// <summary> 2.16.840.1.101.3.4.2.7 </summary>
        public static readonly DerObjectIdentifier IdSha3_224 = HashAlgs.Branch("7");
        /// <summary> 2.16.840.1.101.3.4.2.8 </summary>
        public static readonly DerObjectIdentifier IdSha3_256 = HashAlgs.Branch("8");
        /// <summary> 2.16.840.1.101.3.4.2.9 </summary>
        public static readonly DerObjectIdentifier IdSha3_384 = HashAlgs.Branch("9");
        /// <summary> 2.16.840.1.101.3.4.2.10 </summary>
        public static readonly DerObjectIdentifier IdSha3_512 = HashAlgs.Branch("10");
        /// <summary> 2.16.840.1.101.3.4.2.11 </summary>
        public static readonly DerObjectIdentifier IdShake128 = HashAlgs.Branch("11");
        /// <summary> 2.16.840.1.101.3.4.2.12 </summary>
        public static readonly DerObjectIdentifier IdShake256 = HashAlgs.Branch("12");
        /// <summary> 2.16.840.1.101.3.4.2.13 </summary>
        public static readonly DerObjectIdentifier IdHMacWithSha3_224 = HashAlgs.Branch("13");
        /// <summary> 2.16.840.1.101.3.4.2.14 </summary>
        public static readonly DerObjectIdentifier IdHMacWithSha3_256 = HashAlgs.Branch("14");
        /// <summary> 2.16.840.1.101.3.4.2.15 </summary>
        public static readonly DerObjectIdentifier IdHMacWithSha3_384 = HashAlgs.Branch("15");
        /// <summary> 2.16.840.1.101.3.4.2.16 </summary>
        public static readonly DerObjectIdentifier IdHMacWithSha3_512 = HashAlgs.Branch("16");
        /// <summary> 2.16.840.1.101.3.4.2.17 </summary>
        public static readonly DerObjectIdentifier IdShake128Len = HashAlgs.Branch("17");
        /// <summary> 2.16.840.1.101.3.4.2.18 </summary>
        public static readonly DerObjectIdentifier IdShake256Len = HashAlgs.Branch("18");
        /// <summary> 2.16.840.1.101.3.4.2.19 </summary>
        public static readonly DerObjectIdentifier IdKmacWithShake128 = HashAlgs.Branch("19");
        /// <summary> 2.16.840.1.101.3.4.2.20  </summary>
        public static readonly DerObjectIdentifier IdKmacWithShake256 = HashAlgs.Branch("20");

        /// <summary> 2.16.840.1.101.3.4.1 </summary>
        public static readonly DerObjectIdentifier Aes = NistAlgorithm.Branch("1");
        /// <summary> 2.16.840.1.101.3.4.1.1 </summary>
        public static readonly DerObjectIdentifier IdAes128Ecb = Aes.Branch("1");
        /// <summary> 2.16.840.1.101.3.4.1.2 </summary>
        public static readonly DerObjectIdentifier IdAes128Cbc = Aes.Branch("2");
        /// <summary> 2.16.840.1.101.3.4.1.3 </summary>
        public static readonly DerObjectIdentifier IdAes128Ofb = Aes.Branch("3");
        /// <summary> 2.16.840.1.101.3.4.1.4 </summary>
        public static readonly DerObjectIdentifier IdAes128Cfb = Aes.Branch("4");
        /// <summary> 2.16.840.1.101.3.4.1.5 </summary>
        public static readonly DerObjectIdentifier IdAes128Wrap = Aes.Branch("5");
        /// <summary> 2.16.840.1.101.3.4.1.6 </summary>
        public static readonly DerObjectIdentifier IdAes128Gcm = Aes.Branch("6");
        /// <summary> 2.16.840.1.101.3.4.1.7 </summary>
        public static readonly DerObjectIdentifier IdAes128Ccm = Aes.Branch("7");
        /// <summary> 2.16.840.1.101.3.4.1.8 </summary>
        public static readonly DerObjectIdentifier IdAes128WrapPad = Aes.Branch("8");
        /// <summary> 2.16.840.1.101.3.4.1.9 </summary>
        public static readonly DerObjectIdentifier IdAes128GMac = Aes.Branch("9");

        /// <summary> 2.16.840.1.101.3.4.1.21 </summary>
        public static readonly DerObjectIdentifier IdAes192Ecb = Aes.Branch("21");
        /// <summary> 2.16.840.1.101.3.4.1.22 </summary>
        public static readonly DerObjectIdentifier IdAes192Cbc = Aes.Branch("22");
        /// <summary> 2.16.840.1.101.3.4.1.23 </summary>
        public static readonly DerObjectIdentifier IdAes192Ofb = Aes.Branch("23");
        /// <summary> 2.16.840.1.101.3.4.1.24 </summary>
        public static readonly DerObjectIdentifier IdAes192Cfb = Aes.Branch("24");
        /// <summary> 2.16.840.1.101.3.4.1.25 </summary>
        public static readonly DerObjectIdentifier IdAes192Wrap = Aes.Branch("25");
        /// <summary> 2.16.840.1.101.3.4.1.26 </summary>
        public static readonly DerObjectIdentifier IdAes192Gcm = Aes.Branch("26");
        /// <summary> 2.16.840.1.101.3.4.1.27 </summary>
        public static readonly DerObjectIdentifier IdAes192Ccm = Aes.Branch("27");
        /// <summary> 2.16.840.1.101.3.4.1.28 </summary>
        public static readonly DerObjectIdentifier IdAes192WrapPad = Aes.Branch("28");
        /// <summary> 2.16.840.1.101.3.4.1.29 </summary>
        public static readonly DerObjectIdentifier IdAes192GMac = Aes.Branch("29");

        /// <summary> 2.16.840.1.101.3.4.1.41 </summary>
        public static readonly DerObjectIdentifier IdAes256Ecb = Aes.Branch("41");
        /// <summary> 2.16.840.1.101.3.4.1.42 </summary>
        public static readonly DerObjectIdentifier IdAes256Cbc = Aes.Branch("42");
        /// <summary> 2.16.840.1.101.3.4.1.43 </summary>
        public static readonly DerObjectIdentifier IdAes256Ofb = Aes.Branch("43");
        /// <summary> 2.16.840.1.101.3.4.1.44 </summary>
        public static readonly DerObjectIdentifier IdAes256Cfb = Aes.Branch("44");
        /// <summary> 2.16.840.1.101.3.4.1.45 </summary>
        public static readonly DerObjectIdentifier IdAes256Wrap = Aes.Branch("45");
        /// <summary> 2.16.840.1.101.3.4.1.46 </summary>
        public static readonly DerObjectIdentifier IdAes256Gcm = Aes.Branch("46");
        /// <summary> 2.16.840.1.101.3.4.1.47 </summary>
        public static readonly DerObjectIdentifier IdAes256Ccm = Aes.Branch("47");
        /// <summary> 2.16.840.1.101.3.4.1.48 </summary>
        public static readonly DerObjectIdentifier IdAes256WrapPad = Aes.Branch("48");
        /// <summary> 2.16.840.1.101.3.4.1.49 </summary>
        public static readonly DerObjectIdentifier IdAes256GMac = Aes.Branch("49");

        //
        // signatures
        //
        /// <summary> 2.16.840.1.101.3.4.3 </summary>
        public static readonly DerObjectIdentifier SigAlgs = NistAlgorithm.Branch("3");

        [Obsolete("Use 'SigAlgs' instead")]
        public static readonly DerObjectIdentifier IdDsaWithSha2 = SigAlgs;

        /// <summary> 2.16.840.1.101.3.4.3.1 </summary>
        public static readonly DerObjectIdentifier DsaWithSha224 = SigAlgs.Branch("1");
        /// <summary> 2.16.840.1.101.3.4.3.2 </summary>
        public static readonly DerObjectIdentifier DsaWithSha256 = SigAlgs.Branch("2");
        /// <summary> 2.16.840.1.101.3.4.3.3 </summary>
        public static readonly DerObjectIdentifier DsaWithSha384 = SigAlgs.Branch("3");
        /// <summary> 2.16.840.1.101.3.4.3.4 </summary>
        public static readonly DerObjectIdentifier DsaWithSha512 = SigAlgs.Branch("4");

        /// <summary> 2.16.840.1.101.3.4.3.5 </summary>
        public static readonly DerObjectIdentifier IdDsaWithSha3_224 = SigAlgs.Branch("5");
        /// <summary> 2.16.840.1.101.3.4.3.6 </summary>
        public static readonly DerObjectIdentifier IdDsaWithSha3_256 = SigAlgs.Branch("6");
        /// <summary> 2.16.840.1.101.3.4.3.7 </summary>
        public static readonly DerObjectIdentifier IdDsaWithSha3_384 = SigAlgs.Branch("7");
        /// <summary> 2.16.840.1.101.3.4.3.8 </summary>
        public static readonly DerObjectIdentifier IdDsaWithSha3_512 = SigAlgs.Branch("8");

        // ECDSA with SHA-3
        /// <summary> 2.16.840.1.101.3.4.3.9 </summary>
        public static readonly DerObjectIdentifier IdEcdsaWithSha3_224 = SigAlgs.Branch("9");
        /// <summary> 2.16.840.1.101.3.4.3.10 </summary>
        public static readonly DerObjectIdentifier IdEcdsaWithSha3_256 = SigAlgs.Branch("10");
        /// <summary> 2.16.840.1.101.3.4.3.11 </summary>
        public static readonly DerObjectIdentifier IdEcdsaWithSha3_384 = SigAlgs.Branch("11");
        /// <summary> 2.16.840.1.101.3.4.3.12 </summary>
        public static readonly DerObjectIdentifier IdEcdsaWithSha3_512 = SigAlgs.Branch("12");

        // RSA PKCS #1 v1.5 Signature with SHA-3 family.
        /// <summary> 2.16.840.1.101.3.4.3.13 </summary>
        public static readonly DerObjectIdentifier IdRsassaPkcs1V15WithSha3_224 = SigAlgs.Branch("13");
        /// <summary> 2.16.840.1.101.3.4.3.14 </summary>
        public static readonly DerObjectIdentifier IdRsassaPkcs1V15WithSha3_256 = SigAlgs.Branch("14");
        /// <summary> 2.16.840.1.101.3.4.3.15 </summary>
        public static readonly DerObjectIdentifier IdRsassaPkcs1V15WithSha3_384 = SigAlgs.Branch("15");
        /// <summary> 2.16.840.1.101.3.4.3.16 </summary>
        public static readonly DerObjectIdentifier IdRsassaPkcs1V15WithSha3_512 = SigAlgs.Branch("16");

        // "pure" ML-DSA
        /// <summary> 2.16.840.1.101.3.4.3.17 </summary>
        public static readonly DerObjectIdentifier IdMLDsa44 = SigAlgs.Branch("17");
        /// <summary> 2.16.840.1.101.3.4.3.18 </summary>
        public static readonly DerObjectIdentifier IdMLDsa65 = SigAlgs.Branch("18");
        /// <summary> 2.16.840.1.101.3.4.3.19 </summary>
        public static readonly DerObjectIdentifier IdMLDsa87 = SigAlgs.Branch("19");
        // "pre-hash" ML-DSA
        /// <summary> 2.16.840.1.101.3.4.3.32 /// </summary>
        public static readonly DerObjectIdentifier IdHashMLDsa44WithSha512 = SigAlgs.Branch("32");
        /// <summary> 2.16.840.1.101.3.4.3.33 /// </summary>
        public static readonly DerObjectIdentifier IdHashMLDsa65WithSha512 = SigAlgs.Branch("33");
        /// <summary> 2.16.840.1.101.3.4.3.34 /// </summary>
        public static readonly DerObjectIdentifier IdHashMLDsa87WithSha512 = SigAlgs.Branch("34");
        // "pure" SLH-DSA
        /// <summary> 2.16.840.1.101.3.4.3.20 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaSha2_128s = SigAlgs.Branch("20");
        /// <summary> 2.16.840.1.101.3.4.3.21 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaSha2_128f = SigAlgs.Branch("21");
        /// <summary> 2.16.840.1.101.3.4.3.22 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaSha2_192s = SigAlgs.Branch("22");
        /// <summary> 2.16.840.1.101.3.4.3.23 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaSha2_192f = SigAlgs.Branch("23");
        /// <summary> 2.16.840.1.101.3.4.3.24 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaSha2_256s = SigAlgs.Branch("24");
        /// <summary> 2.16.840.1.101.3.4.3.25 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaSha2_256f = SigAlgs.Branch("25");
        /// <summary> 2.16.840.1.101.3.4.3.26 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaShake128s = SigAlgs.Branch("26");
        /// <summary> 2.16.840.1.101.3.4.3.27 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaShake128f = SigAlgs.Branch("27");
        /// <summary> 2.16.840.1.101.3.4.3.28 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaShake192s = SigAlgs.Branch("28");
        /// <summary> 2.16.840.1.101.3.4.3.29 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaShake192f = SigAlgs.Branch("29");
        /// <summary> 2.16.840.1.101.3.4.3.30 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaShake256s = SigAlgs.Branch("30");
        /// <summary> 2.16.840.1.101.3.4.3.31 </summary>
        public static readonly DerObjectIdentifier IdSlhDsaShake256f = SigAlgs.Branch("31");

        // "pre-hash" SLH-DSA
        /// <summary> 2.16.840.1.101.3.4.3.35 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsaSha2_128sWithSha256 = SigAlgs.Branch("35");
        /// <summary> 2.16.840.1.101.3.4.3.36 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsasha2_128fWithSha256 = SigAlgs.Branch("36");
        /// <summary> 2.16.840.1.101.3.4.3.37 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsasha2_192sWithSha512 = SigAlgs.Branch("37");
        /// <summary> 2.16.840.1.101.3.4.3.38 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsasha2_192fWithSha512 = SigAlgs.Branch("38");
        /// <summary> 2.16.840.1.101.3.4.3.39 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsasha2_256sWithSha512 = SigAlgs.Branch("39");
        /// <summary> 2.16.840.1.101.3.4.3.40 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsasha2_256fWithSha512 = SigAlgs.Branch("40");
        /// <summary> 2.16.840.1.101.3.4.3.41 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsashake_128sWithShake128 = SigAlgs.Branch("41");
        /// <summary> 2.16.840.1.101.3.4.3.42 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsashake_128fWithShake128 = SigAlgs.Branch("42");
        /// <summary> 2.16.840.1.101.3.4.3.43 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsashake_192sWithShake256 = SigAlgs.Branch("43");
        /// <summary> 2.16.840.1.101.3.4.3.44 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsashake_192fWithShake256 = SigAlgs.Branch("44");
        /// <summary> 2.16.840.1.101.3.4.3.45 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsashake_256sWithShake256 = SigAlgs.Branch("45");
        /// <summary> 2.16.840.1.101.3.4.3.46 /// </summary>
        public static readonly DerObjectIdentifier IdHashSlhDsashake_256fWithShake256 = SigAlgs.Branch("46");

        //
        // KEMs - Key-Establishment Mechanisms
        //
        /// <summary> 2.16.840.1.101.3.4.4</summary>
        public static readonly DerObjectIdentifier kems = NistAlgorithm.Branch("4");
        // Ml-Kem
        /// <summary> 2.16.840.1.101.3.4.4.1 </summary>
        public static readonly DerObjectIdentifier IdAlgMLKem512 = kems.Branch("1");
        /// <summary> 2.16.840.1.101.3.4.4.2 </summary>
        public static readonly DerObjectIdentifier IdAlgMLKem768 = kems.Branch("2");
        /// <summary> 2.16.840.1.101.3.4.4.3 </summary>
        public static readonly DerObjectIdentifier IdAlgMLKem1024 = kems.Branch("3");
    }
}
