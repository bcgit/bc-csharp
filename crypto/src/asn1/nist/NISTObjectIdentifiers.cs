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
        public static readonly DerObjectIdentifier NistAlgorithm = new DerObjectIdentifier("2.16.840.1.101.3.4");

        public static readonly DerObjectIdentifier HashAlgs = NistAlgorithm.Branch("2");

        public static readonly DerObjectIdentifier IdSha256             = HashAlgs.Branch("1");
        public static readonly DerObjectIdentifier IdSha384             = HashAlgs.Branch("2");
        public static readonly DerObjectIdentifier IdSha512             = HashAlgs.Branch("3");
        public static readonly DerObjectIdentifier IdSha224             = HashAlgs.Branch("4");
        public static readonly DerObjectIdentifier IdSha512_224         = HashAlgs.Branch("5");
        public static readonly DerObjectIdentifier IdSha512_256         = HashAlgs.Branch("6");
        public static readonly DerObjectIdentifier IdSha3_224           = HashAlgs.Branch("7");
        public static readonly DerObjectIdentifier IdSha3_256           = HashAlgs.Branch("8");
        public static readonly DerObjectIdentifier IdSha3_384           = HashAlgs.Branch("9");
        public static readonly DerObjectIdentifier IdSha3_512           = HashAlgs.Branch("10");
        public static readonly DerObjectIdentifier IdShake128           = HashAlgs.Branch("11");
        public static readonly DerObjectIdentifier IdShake256           = HashAlgs.Branch("12");
        public static readonly DerObjectIdentifier IdHMacWithSha3_224   = HashAlgs.Branch("13");
        public static readonly DerObjectIdentifier IdHMacWithSha3_256   = HashAlgs.Branch("14");
        public static readonly DerObjectIdentifier IdHMacWithSha3_384   = HashAlgs.Branch("15");
        public static readonly DerObjectIdentifier IdHMacWithSha3_512   = HashAlgs.Branch("16");
        public static readonly DerObjectIdentifier IdShake128Len        = HashAlgs.Branch("17");
        public static readonly DerObjectIdentifier IdShake256Len        = HashAlgs.Branch("18");
        public static readonly DerObjectIdentifier IdKmacWithShake128   = HashAlgs.Branch("19");
        public static readonly DerObjectIdentifier IdKmacWithShake256   = HashAlgs.Branch("20");

        public static readonly DerObjectIdentifier Aes = NistAlgorithm.Branch("1");

        public static readonly DerObjectIdentifier IdAes128Ecb      = Aes.Branch("1");
        public static readonly DerObjectIdentifier IdAes128Cbc      = Aes.Branch("2");
        public static readonly DerObjectIdentifier IdAes128Ofb      = Aes.Branch("3");
        public static readonly DerObjectIdentifier IdAes128Cfb      = Aes.Branch("4");
        public static readonly DerObjectIdentifier IdAes128Wrap     = Aes.Branch("5");
        public static readonly DerObjectIdentifier IdAes128Gcm      = Aes.Branch("6");
        public static readonly DerObjectIdentifier IdAes128Ccm      = Aes.Branch("7");
        public static readonly DerObjectIdentifier IdAes128WrapPad  = Aes.Branch("8");
        public static readonly DerObjectIdentifier IdAes128GMac     = Aes.Branch("9");

        public static readonly DerObjectIdentifier IdAes192Ecb      = Aes.Branch("21");
        public static readonly DerObjectIdentifier IdAes192Cbc      = Aes.Branch("22");
        public static readonly DerObjectIdentifier IdAes192Ofb      = Aes.Branch("23");
        public static readonly DerObjectIdentifier IdAes192Cfb      = Aes.Branch("24");
        public static readonly DerObjectIdentifier IdAes192Wrap     = Aes.Branch("25");
        public static readonly DerObjectIdentifier IdAes192Gcm      = Aes.Branch("26");
        public static readonly DerObjectIdentifier IdAes192Ccm      = Aes.Branch("27");
        public static readonly DerObjectIdentifier IdAes192WrapPad  = Aes.Branch("28");
        public static readonly DerObjectIdentifier IdAes192GMac     = Aes.Branch("29");

        public static readonly DerObjectIdentifier IdAes256Ecb      = Aes.Branch("41");
        public static readonly DerObjectIdentifier IdAes256Cbc      = Aes.Branch("42");
        public static readonly DerObjectIdentifier IdAes256Ofb      = Aes.Branch("43");
        public static readonly DerObjectIdentifier IdAes256Cfb      = Aes.Branch("44");
        public static readonly DerObjectIdentifier IdAes256Wrap     = Aes.Branch("45");
        public static readonly DerObjectIdentifier IdAes256Gcm      = Aes.Branch("46");
        public static readonly DerObjectIdentifier IdAes256Ccm      = Aes.Branch("47");
        public static readonly DerObjectIdentifier IdAes256WrapPad  = Aes.Branch("48");
        public static readonly DerObjectIdentifier IdAes256GMac     = Aes.Branch("49");

        //
        // signatures
        //
        public static readonly DerObjectIdentifier SigAlgs = NistAlgorithm.Branch("3");

        [Obsolete("Use 'SigAlgs' instead")]
        public static readonly DerObjectIdentifier IdDsaWithSha2 = SigAlgs;

        public static readonly DerObjectIdentifier DsaWithSha224                = SigAlgs.Branch("1");
        public static readonly DerObjectIdentifier DsaWithSha256                = SigAlgs.Branch("2");
        public static readonly DerObjectIdentifier DsaWithSha384                = SigAlgs.Branch("3");
        public static readonly DerObjectIdentifier DsaWithSha512                = SigAlgs.Branch("4");

        public static readonly DerObjectIdentifier IdDsaWithSha3_224            = SigAlgs.Branch("5");
        public static readonly DerObjectIdentifier IdDsaWithSha3_256            = SigAlgs.Branch("6");
        public static readonly DerObjectIdentifier IdDsaWithSha3_384            = SigAlgs.Branch("7");
        public static readonly DerObjectIdentifier IdDsaWithSha3_512            = SigAlgs.Branch("8");

        // ECDSA with SHA-3
        public static readonly DerObjectIdentifier IdEcdsaWithSha3_224          = SigAlgs.Branch("9");
        public static readonly DerObjectIdentifier IdEcdsaWithSha3_256          = SigAlgs.Branch("10");
        public static readonly DerObjectIdentifier IdEcdsaWithSha3_384          = SigAlgs.Branch("11");
        public static readonly DerObjectIdentifier IdEcdsaWithSha3_512          = SigAlgs.Branch("12");

        // RSA PKCS #1 v1.5 Signature with SHA-3 family.
        public static readonly DerObjectIdentifier IdRsassaPkcs1V15WithSha3_224 = SigAlgs.Branch("13");
        public static readonly DerObjectIdentifier IdRsassaPkcs1V15WithSha3_256 = SigAlgs.Branch("14");
        public static readonly DerObjectIdentifier IdRsassaPkcs1V15WithSha3_384 = SigAlgs.Branch("15");
        public static readonly DerObjectIdentifier IdRsassaPkcs1V15WithSha3_512 = SigAlgs.Branch("16");
    }
}
