using System;

namespace Org.BouncyCastle.Asn1.BC
{
    // TODO[api] Make static
    public abstract class BCObjectIdentifiers
	{
        /**
         * iso.org.dod.internet.private.enterprise.legion-of-the-bouncy-castle
         * <p>1.3.6.1.4.1.22554</p>
         */
        public static readonly DerObjectIdentifier bc = new DerObjectIdentifier("1.3.6.1.4.1.22554");

        /**
         * pbe(1) algorithms
         * <p>1.3.6.1.4.1.22554.1</p>
         */
        public static readonly DerObjectIdentifier bc_pbe        = bc.Branch("1");

        /**
         * SHA-1(1)
         * <p>1.3.6.1.4.1.22554.1.1</p>
         */
        public static readonly DerObjectIdentifier bc_pbe_sha1   = bc_pbe.Branch("1");

        /** SHA-2.SHA-256; 1.3.6.1.4.1.22554.1.2.1 */
        public static readonly DerObjectIdentifier bc_pbe_sha256 = bc_pbe.Branch("2.1");
        /** SHA-2.SHA-384; 1.3.6.1.4.1.22554.1.2.2 */
        public static readonly DerObjectIdentifier bc_pbe_sha384 = bc_pbe.Branch("2.2");
        /** SHA-2.SHA-512; 1.3.6.1.4.1.22554.1.2.3 */
        public static readonly DerObjectIdentifier bc_pbe_sha512 = bc_pbe.Branch("2.3");
        /** SHA-2.SHA-224; 1.3.6.1.4.1.22554.1.2.4 */
        public static readonly DerObjectIdentifier bc_pbe_sha224 = bc_pbe.Branch("2.4");

        /**
         * PKCS-5(1)|PKCS-12(2)
         */
        /** SHA-1.PKCS5;  1.3.6.1.4.1.22554.1.1.1 */
        public static readonly DerObjectIdentifier bc_pbe_sha1_pkcs5    = bc_pbe_sha1.Branch("1");
        /** SHA-1.PKCS12; 1.3.6.1.4.1.22554.1.1.2 */
        public static readonly DerObjectIdentifier bc_pbe_sha1_pkcs12   = bc_pbe_sha1.Branch("2");

        /** SHA-256.PKCS5; 1.3.6.1.4.1.22554.1.2.1.1 */
        public static readonly DerObjectIdentifier bc_pbe_sha256_pkcs5  = bc_pbe_sha256.Branch("1");
        /** SHA-256.PKCS12; 1.3.6.1.4.1.22554.1.2.1.2 */
        public static readonly DerObjectIdentifier bc_pbe_sha256_pkcs12 = bc_pbe_sha256.Branch("2");

        /**
         * AES(1) . (CBC-128(2)|CBC-192(22)|CBC-256(42))
         */
        /** 1.3.6.1.4.1.22554.1.1.2.1.2 */
        public static readonly DerObjectIdentifier bc_pbe_sha1_pkcs12_aes128_cbc   = bc_pbe_sha1_pkcs12.Branch("1.2");
        /** 1.3.6.1.4.1.22554.1.1.2.1.22 */
        public static readonly DerObjectIdentifier bc_pbe_sha1_pkcs12_aes192_cbc   = bc_pbe_sha1_pkcs12.Branch("1.22");
        /** 1.3.6.1.4.1.22554.1.1.2.1.42 */
        public static readonly DerObjectIdentifier bc_pbe_sha1_pkcs12_aes256_cbc   = bc_pbe_sha1_pkcs12.Branch("1.42");

        /** 1.3.6.1.4.1.22554.1.1.2.2.2 */
        public static readonly DerObjectIdentifier bc_pbe_sha256_pkcs12_aes128_cbc = bc_pbe_sha256_pkcs12.Branch("1.2");
        /** 1.3.6.1.4.1.22554.1.1.2.2.22 */
        public static readonly DerObjectIdentifier bc_pbe_sha256_pkcs12_aes192_cbc = bc_pbe_sha256_pkcs12.Branch("1.22");
        /** 1.3.6.1.4.1.22554.1.1.2.2.42 */
        public static readonly DerObjectIdentifier bc_pbe_sha256_pkcs12_aes256_cbc = bc_pbe_sha256_pkcs12.Branch("1.42");

        /**
         * signature(2) algorithms
         */
        public static readonly DerObjectIdentifier bc_sig        = bc.Branch("2");

        /**
         * Sphincs-256
         */
        public static readonly DerObjectIdentifier sphincs256                      = bc_sig.Branch("1");
        public static readonly DerObjectIdentifier sphincs256_with_BLAKE512        = sphincs256.Branch("1");
        public static readonly DerObjectIdentifier sphincs256_with_SHA512          = sphincs256.Branch("2");
        public static readonly DerObjectIdentifier sphincs256_with_SHA3_512        = sphincs256.Branch("3");

        /**
         * XMSS
         */
        public static readonly DerObjectIdentifier xmss = bc_sig.Branch("2");
        public static readonly DerObjectIdentifier xmss_SHA256ph = xmss.Branch("1");
        public static readonly DerObjectIdentifier xmss_SHA512ph = xmss.Branch("2");
        public static readonly DerObjectIdentifier xmss_SHAKE128ph = xmss.Branch("3");
        public static readonly DerObjectIdentifier xmss_SHAKE256ph = xmss.Branch("4");
        public static readonly DerObjectIdentifier xmss_SHA256 = xmss.Branch("5");
        public static readonly DerObjectIdentifier xmss_SHA512 = xmss.Branch("6");
        public static readonly DerObjectIdentifier xmss_SHAKE128 = xmss.Branch("7");
        public static readonly DerObjectIdentifier xmss_SHAKE256 = xmss.Branch("8");

        /**
         * XMSS^MT
         */
        public static readonly DerObjectIdentifier xmss_mt = bc_sig.Branch("3");
        public static readonly DerObjectIdentifier xmss_mt_SHA256ph = xmss_mt.Branch("1");
        public static readonly DerObjectIdentifier xmss_mt_SHA512ph = xmss_mt.Branch("2");
        public static readonly DerObjectIdentifier xmss_mt_SHAKE128ph = xmss_mt.Branch("3");
        public static readonly DerObjectIdentifier xmss_mt_SHAKE256ph = xmss_mt.Branch("4");
        public static readonly DerObjectIdentifier xmss_mt_SHA256 = xmss_mt.Branch("5");
        public static readonly DerObjectIdentifier xmss_mt_SHA512 = xmss_mt.Branch("6");
        public static readonly DerObjectIdentifier xmss_mt_SHAKE128 = xmss_mt.Branch("7");
        public static readonly DerObjectIdentifier xmss_mt_SHAKE256 = xmss_mt.Branch("8");

        [Obsolete("Use 'xmss_SHA256ph' instead")]
        public static readonly DerObjectIdentifier xmss_with_SHA256 = xmss_SHA256ph;
        [Obsolete("Use 'xmss_SHA512ph' instead")]
        public static readonly DerObjectIdentifier xmss_with_SHA512 = xmss_SHA512ph;
        [Obsolete("Use 'xmss_SHAKE128ph' instead")]
        public static readonly DerObjectIdentifier xmss_with_SHAKE128 = xmss_SHAKE128ph;
        [Obsolete("Use 'xmss_SHAKE256ph' instead")]
        public static readonly DerObjectIdentifier xmss_with_SHAKE256 = xmss_SHAKE256ph;

        [Obsolete("Use 'xmss_mt_SHA256ph' instead")]
        public static readonly DerObjectIdentifier xmss_mt_with_SHA256 = xmss_mt_SHA256ph;
        [Obsolete("Use 'xmss_mt_SHA512ph' instead")]
        public static readonly DerObjectIdentifier xmss_mt_with_SHA512 = xmss_mt_SHA512ph;
        [Obsolete("Use 'xmss_mt_SHAKE128ph' instead")]
        public static readonly DerObjectIdentifier xmss_mt_with_SHAKE128 = xmss_mt_SHAKE128ph;
        [Obsolete("Use 'xmss_mt_SHAKE256ph' instead")]
        public static readonly DerObjectIdentifier xmss_mt_with_SHAKE256 = xmss_mt_SHAKE256ph;

        /**
         * qTESLA
         */
        public static readonly DerObjectIdentifier qTESLA = bc_sig.Branch("4");

        public static readonly DerObjectIdentifier qTESLA_Rnd1_I = qTESLA.Branch("1");
        public static readonly DerObjectIdentifier qTESLA_Rnd1_III_size = qTESLA.Branch("2");
        public static readonly DerObjectIdentifier qTESLA_Rnd1_III_speed = qTESLA.Branch("3");
        public static readonly DerObjectIdentifier qTESLA_Rnd1_p_I = qTESLA.Branch("4");
        public static readonly DerObjectIdentifier qTESLA_Rnd1_p_III = qTESLA.Branch("5");

        public static readonly DerObjectIdentifier qTESLA_p_I = qTESLA.Branch("11");
        public static readonly DerObjectIdentifier qTESLA_p_III = qTESLA.Branch("12");

        /**
         * SPHINCS+
         */
        public static readonly DerObjectIdentifier sphincsPlus = bc_sig.Branch("5");
        public static readonly DerObjectIdentifier sphincsPlus_sha2_128s_r3 = sphincsPlus.Branch("1");
        public static readonly DerObjectIdentifier sphincsPlus_sha2_128f_r3 = sphincsPlus.Branch("2");
        public static readonly DerObjectIdentifier sphincsPlus_shake_128s_r3 = sphincsPlus.Branch("3");
        public static readonly DerObjectIdentifier sphincsPlus_shake_128f_r3 = sphincsPlus.Branch("4");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_128s_r3 = sphincsPlus.Branch("5");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_128f_r3 = sphincsPlus.Branch("6");

        public static readonly DerObjectIdentifier sphincsPlus_sha2_192s_r3 = sphincsPlus.Branch("7");
        public static readonly DerObjectIdentifier sphincsPlus_sha2_192f_r3 = sphincsPlus.Branch("8");
        public static readonly DerObjectIdentifier sphincsPlus_shake_192s_r3 = sphincsPlus.Branch("9");
        public static readonly DerObjectIdentifier sphincsPlus_shake_192f_r3 = sphincsPlus.Branch("10");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_192s_r3 = sphincsPlus.Branch("11");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_192f_r3 = sphincsPlus.Branch("12");

        public static readonly DerObjectIdentifier sphincsPlus_sha2_256s_r3 = sphincsPlus.Branch("13");
        public static readonly DerObjectIdentifier sphincsPlus_sha2_256f_r3 = sphincsPlus.Branch("14");
        public static readonly DerObjectIdentifier sphincsPlus_shake_256s_r3 = sphincsPlus.Branch("15");
        public static readonly DerObjectIdentifier sphincsPlus_shake_256f_r3 = sphincsPlus.Branch("16");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_256s_r3 = sphincsPlus.Branch("17");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_256f_r3 = sphincsPlus.Branch("18");

        public static readonly DerObjectIdentifier sphincsPlus_sha2_128s_r3_simple = sphincsPlus.Branch("19");
        public static readonly DerObjectIdentifier sphincsPlus_sha2_128f_r3_simple = sphincsPlus.Branch("20");
        public static readonly DerObjectIdentifier sphincsPlus_shake_128s_r3_simple = sphincsPlus.Branch("21");
        public static readonly DerObjectIdentifier sphincsPlus_shake_128f_r3_simple = sphincsPlus.Branch("22");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_128s_r3_simple = sphincsPlus.Branch("23");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_128f_r3_simple = sphincsPlus.Branch("24");

        public static readonly DerObjectIdentifier sphincsPlus_sha2_192s_r3_simple = sphincsPlus.Branch("25");
        public static readonly DerObjectIdentifier sphincsPlus_sha2_192f_r3_simple = sphincsPlus.Branch("26");
        public static readonly DerObjectIdentifier sphincsPlus_shake_192s_r3_simple = sphincsPlus.Branch("27");
        public static readonly DerObjectIdentifier sphincsPlus_shake_192f_r3_simple = sphincsPlus.Branch("28");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_192s_r3_simple = sphincsPlus.Branch("29");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_192f_r3_simple = sphincsPlus.Branch("30");

        public static readonly DerObjectIdentifier sphincsPlus_sha2_256s_r3_simple = sphincsPlus.Branch("31");
        public static readonly DerObjectIdentifier sphincsPlus_sha2_256f_r3_simple = sphincsPlus.Branch("32");
        public static readonly DerObjectIdentifier sphincsPlus_shake_256s_r3_simple = sphincsPlus.Branch("33");
        public static readonly DerObjectIdentifier sphincsPlus_shake_256f_r3_simple = sphincsPlus.Branch("34");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_256s_r3_simple = sphincsPlus.Branch("35");
        public static readonly DerObjectIdentifier sphincsPlus_haraka_256f_r3_simple = sphincsPlus.Branch("36");

        // Interop OIDs.
        public static readonly DerObjectIdentifier sphincsPlus_sha2_128s_simple = new DerObjectIdentifier("1.3.9999.6.4.16");
        public static readonly DerObjectIdentifier sphincsPlus_sha2_128f_simple = new DerObjectIdentifier("1.3.9999.6.4.13");
        public static readonly DerObjectIdentifier sphincsPlus_shake_128f_simple = new DerObjectIdentifier("1.3.9999.6.7.4");

        public static readonly DerObjectIdentifier sphincsPlus_sha2_192s_simple = new DerObjectIdentifier("1.3.9999.6.5.12");
        public static readonly DerObjectIdentifier sphincsPlus_sha2_192f_simple = new DerObjectIdentifier("1.3.9999.6.5.10");
        public static readonly DerObjectIdentifier sphincsPlus_shake_192f_simple = new DerObjectIdentifier("1.3.9999.6.8.3");
    
        public static readonly DerObjectIdentifier sphincsPlus_sha2_256s_simple = new DerObjectIdentifier("1.3.9999.6.6.12");
        public static readonly DerObjectIdentifier sphincsPlus_sha2_256f_simple = new DerObjectIdentifier("1.3.9999.6.6.10");
        public static readonly DerObjectIdentifier sphincsPlus_shake_256f_simple = new DerObjectIdentifier("1.3.9999.6.9.3");

        [Obsolete("Will be removed - name is erroneous")]
        public static readonly DerObjectIdentifier sphincsPlus_shake_256 = sphincsPlus.Branch("1");
        [Obsolete("Will be removed - name is erroneous")]
        public static readonly DerObjectIdentifier sphincsPlus_sha_256 = sphincsPlus.Branch("2");
        [Obsolete("Will be removed - name is erroneous")]
        public static readonly DerObjectIdentifier sphincsPlus_sha_512 = sphincsPlus.Branch("3");

        /**
         * Picnic
         */
        public static readonly DerObjectIdentifier picnic = bc_sig.Branch("6");
        public static readonly DerObjectIdentifier picnicl1fs = picnic.Branch("1");
        public static readonly DerObjectIdentifier picnicl1ur = picnic.Branch("2");
        public static readonly DerObjectIdentifier picnicl3fs = picnic.Branch("3");
        public static readonly DerObjectIdentifier picnicl3ur = picnic.Branch("4");
        public static readonly DerObjectIdentifier picnicl5fs = picnic.Branch("5");
        public static readonly DerObjectIdentifier picnicl5ur = picnic.Branch("6");
        public static readonly DerObjectIdentifier picnic3l1 = picnic.Branch("7");
        public static readonly DerObjectIdentifier picnic3l3 = picnic.Branch("8");
        public static readonly DerObjectIdentifier picnic3l5 = picnic.Branch("9");
        public static readonly DerObjectIdentifier picnicl1full = picnic.Branch("10");
        public static readonly DerObjectIdentifier picnicl3full = picnic.Branch("11");
        public static readonly DerObjectIdentifier picnicl5full = picnic.Branch("12");

        public static readonly DerObjectIdentifier picnic_signature = picnic.Branch("2");
        public static readonly DerObjectIdentifier picnic_with_sha512 = picnic_signature.Branch("1");
        public static readonly DerObjectIdentifier picnic_with_shake256 = picnic_signature.Branch("2");
        public static readonly DerObjectIdentifier picnic_with_sha3_512 = picnic_signature.Branch("3");

        /*
         * Falcon
         */
        public static readonly DerObjectIdentifier falcon = bc_sig.Branch("7");

        public static readonly DerObjectIdentifier falcon_512 = new DerObjectIdentifier("1.3.9999.3.1");  // falcon.branch("1");
        public static readonly DerObjectIdentifier falcon_1024 =  new DerObjectIdentifier("1.3.9999.3.4"); // falcon.branch("2");

        /*
         * Dilithium
         */
        public static readonly DerObjectIdentifier dilithium = bc_sig.Branch("8");

        // OpenSSL OIDs
        public static readonly DerObjectIdentifier dilithium2 = new DerObjectIdentifier("1.3.6.1.4.1.2.267.7.4.4"); // dilithium.branch("1");
        public static readonly DerObjectIdentifier dilithium3 = new DerObjectIdentifier("1.3.6.1.4.1.2.267.7.6.5"); // dilithium.branch("2");
        public static readonly DerObjectIdentifier dilithium5 = new DerObjectIdentifier("1.3.6.1.4.1.2.267.7.8.7"); // dilithium.branch("3");
        public static readonly DerObjectIdentifier dilithium2_aes = new DerObjectIdentifier("1.3.6.1.4.1.2.267.11.4.4"); // dilithium.branch("4");
        public static readonly DerObjectIdentifier dilithium3_aes = new DerObjectIdentifier("1.3.6.1.4.1.2.267.11.6.5"); // dilithium.branch("5");
        public static readonly DerObjectIdentifier dilithium5_aes = new DerObjectIdentifier("1.3.6.1.4.1.2.267.11.8.7"); // dilithium.branch("6");

        /*
         * Rainbow
         */
        public static readonly DerObjectIdentifier rainbow = bc_sig.Branch("9");

        public static readonly DerObjectIdentifier rainbow_III_classic = rainbow.Branch("1");
        public static readonly DerObjectIdentifier rainbow_III_circumzenithal = rainbow.Branch("2");
        public static readonly DerObjectIdentifier rainbow_III_compressed = rainbow.Branch("3");
        public static readonly DerObjectIdentifier rainbow_V_classic = rainbow.Branch("4");
        public static readonly DerObjectIdentifier rainbow_V_circumzenithal = rainbow.Branch("5");
        public static readonly DerObjectIdentifier rainbow_V_compressed = rainbow.Branch("6");

        /**
         * key_exchange(3) algorithms
         */
        public static readonly DerObjectIdentifier bc_exch = bc.Branch("3");

        /**
         * NewHope
         */
        public static readonly DerObjectIdentifier newHope = bc_exch.Branch("1");

        /**
         * X.509 extension(4) values
         * <p/>
         * 1.3.6.1.4.1.22554.4
         */
        public static readonly DerObjectIdentifier bc_ext = bc.Branch("4");

        public static readonly DerObjectIdentifier linkedCertificate = bc_ext.Branch("1");
        public static readonly DerObjectIdentifier external_value = bc_ext.Branch("2");

        /**
         * KEM(4) algorithms
         */
        public static readonly DerObjectIdentifier bc_kem = bc.Branch("5");

        /**
         * Classic McEliece
         */
        public static readonly DerObjectIdentifier pqc_kem_mceliece = bc_kem.Branch("1");

        public static readonly DerObjectIdentifier mceliece348864_r3 = pqc_kem_mceliece.Branch("1");
        public static readonly DerObjectIdentifier mceliece348864f_r3 = pqc_kem_mceliece.Branch("2");
        public static readonly DerObjectIdentifier mceliece460896_r3 = pqc_kem_mceliece.Branch("3");
        public static readonly DerObjectIdentifier mceliece460896f_r3 = pqc_kem_mceliece.Branch("4");
        public static readonly DerObjectIdentifier mceliece6688128_r3 = pqc_kem_mceliece.Branch("5");
        public static readonly DerObjectIdentifier mceliece6688128f_r3 = pqc_kem_mceliece.Branch("6");
        public static readonly DerObjectIdentifier mceliece6960119_r3 = pqc_kem_mceliece.Branch("7");
        public static readonly DerObjectIdentifier mceliece6960119f_r3 = pqc_kem_mceliece.Branch("8");
        public static readonly DerObjectIdentifier mceliece8192128_r3 = pqc_kem_mceliece.Branch("9");
        public static readonly DerObjectIdentifier mceliece8192128f_r3 = pqc_kem_mceliece.Branch("10");

        /**
         * Frodo
         */
        public static readonly DerObjectIdentifier pqc_kem_frodo = bc_kem.Branch("2");

        public static readonly DerObjectIdentifier frodokem640aes = pqc_kem_frodo.Branch("1");
        public static readonly DerObjectIdentifier frodokem640shake = pqc_kem_frodo.Branch("2");
        public static readonly DerObjectIdentifier frodokem976aes = pqc_kem_frodo.Branch("3");
        public static readonly DerObjectIdentifier frodokem976shake = pqc_kem_frodo.Branch("4");
        public static readonly DerObjectIdentifier frodokem1344aes = pqc_kem_frodo.Branch("5");
        public static readonly DerObjectIdentifier frodokem1344shake = pqc_kem_frodo.Branch("6");

        /**
         * SABER
         */
        public static readonly DerObjectIdentifier pqc_kem_saber = bc_kem.Branch("3");

        public static readonly DerObjectIdentifier lightsaberkem128r3 = pqc_kem_saber.Branch("1");
        public static readonly DerObjectIdentifier saberkem128r3 = pqc_kem_saber.Branch("2");
        public static readonly DerObjectIdentifier firesaberkem128r3 = pqc_kem_saber.Branch("3");
        public static readonly DerObjectIdentifier lightsaberkem192r3 = pqc_kem_saber.Branch("4");
        public static readonly DerObjectIdentifier saberkem192r3 = pqc_kem_saber.Branch("5");
        public static readonly DerObjectIdentifier firesaberkem192r3 = pqc_kem_saber.Branch("6");
        public static readonly DerObjectIdentifier lightsaberkem256r3 = pqc_kem_saber.Branch("7");
        public static readonly DerObjectIdentifier saberkem256r3 = pqc_kem_saber.Branch("8");
        public static readonly DerObjectIdentifier firesaberkem256r3 = pqc_kem_saber.Branch("9");
        public static readonly DerObjectIdentifier ulightsaberkemr3 = pqc_kem_saber.Branch("10");
        public static readonly DerObjectIdentifier usaberkemr3 = pqc_kem_saber.Branch("11");
        public static readonly DerObjectIdentifier ufiresaberkemr3 = pqc_kem_saber.Branch("12");
        public static readonly DerObjectIdentifier lightsaberkem90sr3 = pqc_kem_saber.Branch("13");
        public static readonly DerObjectIdentifier saberkem90sr3 = pqc_kem_saber.Branch("14");
        public static readonly DerObjectIdentifier firesaberkem90sr3 = pqc_kem_saber.Branch("15");
        public static readonly DerObjectIdentifier ulightsaberkem90sr3 = pqc_kem_saber.Branch("16");
        public static readonly DerObjectIdentifier usaberkem90sr3 = pqc_kem_saber.Branch("17");
        public static readonly DerObjectIdentifier ufiresaberkem90sr3 = pqc_kem_saber.Branch("18");

        /**
         * SIKE
         */
        public static readonly DerObjectIdentifier pqc_kem_sike = bc_kem.Branch("4");

        public static readonly DerObjectIdentifier sikep434 = pqc_kem_sike.Branch("1");
        public static readonly DerObjectIdentifier sikep503 = pqc_kem_sike.Branch("2");
        public static readonly DerObjectIdentifier sikep610 = pqc_kem_sike.Branch("3");
        public static readonly DerObjectIdentifier sikep751 = pqc_kem_sike.Branch("4");
        public static readonly DerObjectIdentifier sikep434_compressed = pqc_kem_sike.Branch("5");
        public static readonly DerObjectIdentifier sikep503_compressed = pqc_kem_sike.Branch("6");
        public static readonly DerObjectIdentifier sikep610_compressed = pqc_kem_sike.Branch("7");
        public static readonly DerObjectIdentifier sikep751_compressed = pqc_kem_sike.Branch("8");

        /**
         * NTRU
         */
        public static readonly DerObjectIdentifier pqc_kem_ntru = bc_kem.Branch("5");

        public static readonly DerObjectIdentifier ntruhps2048509 = pqc_kem_ntru.Branch("1");
        public static readonly DerObjectIdentifier ntruhps2048677 = pqc_kem_ntru.Branch("2");
        public static readonly DerObjectIdentifier ntruhps4096821 = pqc_kem_ntru.Branch("3");
        public static readonly DerObjectIdentifier ntruhrss701 = pqc_kem_ntru.Branch("4");

        /**
         * Kyber
         */
        public static readonly DerObjectIdentifier pqc_kem_kyber = bc_kem.Branch("6");

        public static readonly DerObjectIdentifier kyber512 = pqc_kem_kyber.Branch("1");
        public static readonly DerObjectIdentifier kyber768 = pqc_kem_kyber.Branch("2");
        public static readonly DerObjectIdentifier kyber1024 = pqc_kem_kyber.Branch("3");
        public static readonly DerObjectIdentifier kyber512_aes = pqc_kem_kyber.Branch("4");
        public static readonly DerObjectIdentifier kyber768_aes = pqc_kem_kyber.Branch("5");
        public static readonly DerObjectIdentifier kyber1024_aes = pqc_kem_kyber.Branch("6");

        /**
         * NTRUPrime
         */
        public static readonly DerObjectIdentifier pqc_kem_ntruprime = bc_kem.Branch("7");

        public static readonly DerObjectIdentifier pqc_kem_ntrulprime = pqc_kem_ntruprime.Branch("1");
        public static readonly DerObjectIdentifier ntrulpr653 = pqc_kem_ntrulprime.Branch("1");
        public static readonly DerObjectIdentifier ntrulpr761 = pqc_kem_ntrulprime.Branch("2");
        public static readonly DerObjectIdentifier ntrulpr857 = pqc_kem_ntrulprime.Branch("3");
        public static readonly DerObjectIdentifier ntrulpr953 = pqc_kem_ntrulprime.Branch("4");
        public static readonly DerObjectIdentifier ntrulpr1013 = pqc_kem_ntrulprime.Branch("5");
        public static readonly DerObjectIdentifier ntrulpr1277 = pqc_kem_ntrulprime.Branch("6");

        public static readonly DerObjectIdentifier pqc_kem_sntruprime = pqc_kem_ntruprime.Branch("2");
        public static readonly DerObjectIdentifier sntrup653 = pqc_kem_sntruprime.Branch("1");
        public static readonly DerObjectIdentifier sntrup761 = pqc_kem_sntruprime.Branch("2");
        public static readonly DerObjectIdentifier sntrup857 = pqc_kem_sntruprime.Branch("3");
        public static readonly DerObjectIdentifier sntrup953 = pqc_kem_sntruprime.Branch("4");
        public static readonly DerObjectIdentifier sntrup1013 = pqc_kem_sntruprime.Branch("5");
        public static readonly DerObjectIdentifier sntrup1277 = pqc_kem_sntruprime.Branch("6");

        /**
         * BIKE
         */
        public static readonly DerObjectIdentifier pqc_kem_bike = bc_kem.Branch("8");

        public static readonly DerObjectIdentifier bike128 = pqc_kem_bike.Branch("1");
        public static readonly DerObjectIdentifier bike192 = pqc_kem_bike.Branch("2");
        public static readonly DerObjectIdentifier bike256 = pqc_kem_bike.Branch("3");

        /**
         * HQC
         */
        public static readonly DerObjectIdentifier pqc_kem_hqc = bc_kem.Branch("9");

        public static readonly DerObjectIdentifier hqc128 = pqc_kem_hqc.Branch("1");
        public static readonly DerObjectIdentifier hqc192 = pqc_kem_hqc.Branch("2");
        public static readonly DerObjectIdentifier hqc256 = pqc_kem_hqc.Branch("3");
    }
}
