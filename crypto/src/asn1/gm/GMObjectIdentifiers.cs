using System;

namespace Org.BouncyCastle.Asn1.GM
{
    /// <summary>Object identifiers for the Chinese national (GM/T) cryptographic standards.</summary>
    // TODO[api] Make static
    public abstract class GMObjectIdentifiers
    {
        /// <summary>The object identifier <c>1.2.156.10197.1</c>.</summary>
        public static readonly DerObjectIdentifier sm_scheme = new DerObjectIdentifier("1.2.156.10197.1");

        /// <summary>The object identifier <c>1.2.156.10197.1.101.1</c>.</summary>
        public static readonly DerObjectIdentifier sm6_ecb = sm_scheme.Branch("101.1");
        /// <summary>The object identifier <c>1.2.156.10197.1.101.2</c>.</summary>
        public static readonly DerObjectIdentifier sm6_cbc = sm_scheme.Branch("101.2");
        /// <summary>The object identifier <c>1.2.156.10197.1.101.3</c>.</summary>
        public static readonly DerObjectIdentifier sm6_ofb128 = sm_scheme.Branch("101.3");
        /// <summary>The object identifier <c>1.2.156.10197.1.101.4</c>.</summary>
        public static readonly DerObjectIdentifier sm6_cfb128 = sm_scheme.Branch("101.4");

        /// <summary>The object identifier <c>1.2.156.10197.1.102.1</c>.</summary>
        public static readonly DerObjectIdentifier sm1_ecb = sm_scheme.Branch("102.1");
        /// <summary>The object identifier <c>1.2.156.10197.1.102.2</c>.</summary>
        public static readonly DerObjectIdentifier sm1_cbc = sm_scheme.Branch("102.2");
        /// <summary>The object identifier <c>1.2.156.10197.1.102.3</c>.</summary>
        public static readonly DerObjectIdentifier sm1_ofb128 = sm_scheme.Branch("102.3");
        /// <summary>The object identifier <c>1.2.156.10197.1.102.4</c>.</summary>
        public static readonly DerObjectIdentifier sm1_cfb128 = sm_scheme.Branch("102.4");
        /// <summary>The object identifier <c>1.2.156.10197.1.102.5</c>.</summary>
        public static readonly DerObjectIdentifier sm1_cfb1 = sm_scheme.Branch("102.5");
        /// <summary>The object identifier <c>1.2.156.10197.1.102.6</c>.</summary>
        public static readonly DerObjectIdentifier sm1_cfb8 = sm_scheme.Branch("102.6");

        /// <summary>The object identifier <c>1.2.156.10197.1.103.1</c>.</summary>
        public static readonly DerObjectIdentifier ssf33_ecb = sm_scheme.Branch("103.1");
        /// <summary>The object identifier <c>1.2.156.10197.1.103.2</c>.</summary>
        public static readonly DerObjectIdentifier ssf33_cbc = sm_scheme.Branch("103.2");
        /// <summary>The object identifier <c>1.2.156.10197.1.103.3</c>.</summary>
        public static readonly DerObjectIdentifier ssf33_ofb128 = sm_scheme.Branch("103.3");
        /// <summary>The object identifier <c>1.2.156.10197.1.103.4</c>.</summary>
        public static readonly DerObjectIdentifier ssf33_cfb128 = sm_scheme.Branch("103.4");
        /// <summary>The object identifier <c>1.2.156.10197.1.103.5</c>.</summary>
        public static readonly DerObjectIdentifier ssf33_cfb1 = sm_scheme.Branch("103.5");
        /// <summary>The object identifier <c>1.2.156.10197.1.103.6</c>.</summary>
        public static readonly DerObjectIdentifier ssf33_cfb8 = sm_scheme.Branch("103.6");

        /// <summary>The object identifier <c>1.2.156.10197.1.104.1</c>.</summary>
        public static readonly DerObjectIdentifier sms4_ecb = sm_scheme.Branch("104.1");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.2</c>.</summary>
        public static readonly DerObjectIdentifier sms4_cbc = sm_scheme.Branch("104.2");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.3</c>.</summary>
        public static readonly DerObjectIdentifier sms4_ofb128 = sm_scheme.Branch("104.3");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.4</c>.</summary>
        public static readonly DerObjectIdentifier sms4_cfb128 = sm_scheme.Branch("104.4");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.5</c>.</summary>
        public static readonly DerObjectIdentifier sms4_cfb1 = sm_scheme.Branch("104.5");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.6</c>.</summary>
        public static readonly DerObjectIdentifier sms4_cfb8 = sm_scheme.Branch("104.6");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.7</c>.</summary>
        public static readonly DerObjectIdentifier sms4_ctr = sm_scheme.Branch("104.7");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.8</c>.</summary>
        public static readonly DerObjectIdentifier sms4_gcm = sm_scheme.Branch("104.8");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.9</c>.</summary>
        public static readonly DerObjectIdentifier sms4_ccm = sm_scheme.Branch("104.9");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.10</c>.</summary>
        public static readonly DerObjectIdentifier sms4_xts = sm_scheme.Branch("104.10");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.11</c>.</summary>
        public static readonly DerObjectIdentifier sms4_wrap = sm_scheme.Branch("104.11");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.12</c>.</summary>
        public static readonly DerObjectIdentifier sms4_wrap_pad = sm_scheme.Branch("104.12");
        /// <summary>The object identifier <c>1.2.156.10197.1.104.100</c>.</summary>
        public static readonly DerObjectIdentifier sms4_ocb = sm_scheme.Branch("104.100");

        /// <summary>The object identifier <c>1.2.156.10197.1.201</c>.</summary>
        public static readonly DerObjectIdentifier sm5 = sm_scheme.Branch("201");

        /// <summary>The object identifier <c>1.2.156.10197.1.301</c>.</summary>
        public static readonly DerObjectIdentifier sm2p256v1 = sm_scheme.Branch("301");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.1</c>.</summary>
        public static readonly DerObjectIdentifier sm2sign = sm_scheme.Branch("301.1");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.2</c>.</summary>
        public static readonly DerObjectIdentifier sm2exchange = sm_scheme.Branch("301.2");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt = sm_scheme.Branch("301.3");

        /**
         * &lt;Information security technology — Cryptographic application identifier criterion specification&gt;
         * <url>http://c.gb688.cn/bzgk/gb/showGb?type=online&amp;hcno=252CF0F72A7BE339A56DEA7D774E8994</url>,
         * Page 21 only cover from 301.1 to 301.3
         */
        public static readonly DerObjectIdentifier wapip192v1 = sm_scheme.Branch("301.101");

        /**
         * &lt;WAPI certificate management—Part 5: Example of certificate format (draft)&gt;
         * <url>http://www.chinabwips.org.cn/zqyjgs1.htm</url> and
         * <url>http://www.chinabwips.org.cn/doc/101.pdf</url>,
         * Page 9 and page 10 states the OID of ECDSA-192 algorithm based on SHA-256 is 1.2.156.11235.1.1.1
         * */
        public static readonly DerObjectIdentifier wapi192v1 = new DerObjectIdentifier("1.2.156.11235.1.1.1");
        /// <summary>The object identifier <c>1.2.156.11235.1.1.2.1</c>.</summary>
        public static readonly DerObjectIdentifier wapi192v1_parameters = new DerObjectIdentifier("1.2.156.11235.1.1.2.1");

        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.1</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_recommendedParameters = sm2encrypt.Branch("1");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_specifiedParameters = sm2encrypt.Branch("2");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2.1</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_with_sm3 = sm2encrypt.Branch("2.1");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2.2</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_with_sha1 = sm2encrypt.Branch("2.2");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2.3</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_with_sha224 = sm2encrypt.Branch("2.3");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2.4</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_with_sha256 = sm2encrypt.Branch("2.4");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2.5</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_with_sha384 = sm2encrypt.Branch("2.5");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2.6</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_with_sha512 = sm2encrypt.Branch("2.6");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2.7</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_with_rmd160 = sm2encrypt.Branch("2.7");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2.8</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_with_whirlpool = sm2encrypt.Branch("2.8");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2.9</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_with_blake2b512 = sm2encrypt.Branch("2.9");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2.10</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_with_blake2s256 = sm2encrypt.Branch("2.10");
        /// <summary>The object identifier <c>1.2.156.10197.1.301.3.2.11</c>.</summary>
        public static readonly DerObjectIdentifier sm2encrypt_with_md5 = sm2encrypt.Branch("2.11");

        /// <summary>The object identifier <c>1.2.156.10197.1.302</c>.</summary>
        public static readonly DerObjectIdentifier id_sm9PublicKey = sm_scheme.Branch("302");
        /// <summary>The object identifier <c>1.2.156.10197.1.302.1</c>.</summary>
        public static readonly DerObjectIdentifier sm9sign = sm_scheme.Branch("302.1");
        /// <summary>The object identifier <c>1.2.156.10197.1.302.2</c>.</summary>
        public static readonly DerObjectIdentifier sm9keyagreement = sm_scheme.Branch("302.2");
        /// <summary>The object identifier <c>1.2.156.10197.1.302.3</c>.</summary>
        public static readonly DerObjectIdentifier sm9encrypt = sm_scheme.Branch("302.3");

        /// <summary>The object identifier <c>1.2.156.10197.1.401</c>.</summary>
        public static readonly DerObjectIdentifier sm3 = sm_scheme.Branch("401");

        /// <summary>The object identifier <c>1.2.156.10197.1.401.2</c>.</summary>
        public static readonly DerObjectIdentifier hmac_sm3 = sm3.Branch("2");

        /// <summary>The object identifier <c>1.2.156.10197.1.501</c>.</summary>
        public static readonly DerObjectIdentifier sm2sign_with_sm3 = sm_scheme.Branch("501");
        /// <summary>The object identifier <c>1.2.156.10197.1.502</c>.</summary>
        public static readonly DerObjectIdentifier sm2sign_with_sha1 = sm_scheme.Branch("502");
        /// <summary>The object identifier <c>1.2.156.10197.1.503</c>.</summary>
        public static readonly DerObjectIdentifier sm2sign_with_sha256 = sm_scheme.Branch("503");
        /// <summary>The object identifier <c>1.2.156.10197.1.504</c>.</summary>
        public static readonly DerObjectIdentifier sm2sign_with_sha512 = sm_scheme.Branch("504");
        /// <summary>The object identifier <c>1.2.156.10197.1.505</c>.</summary>
        public static readonly DerObjectIdentifier sm2sign_with_sha224 = sm_scheme.Branch("505");
        /// <summary>The object identifier <c>1.2.156.10197.1.506</c>.</summary>
        public static readonly DerObjectIdentifier sm2sign_with_sha384 = sm_scheme.Branch("506");
        /// <summary>The object identifier <c>1.2.156.10197.1.507</c>.</summary>
        public static readonly DerObjectIdentifier sm2sign_with_rmd160 = sm_scheme.Branch("507");
        /// <summary>The object identifier <c>1.2.156.10197.1.520</c>.</summary>
        public static readonly DerObjectIdentifier sm2sign_with_whirlpool = sm_scheme.Branch("520");
        /// <summary>The object identifier <c>1.2.156.10197.1.521</c>.</summary>
        public static readonly DerObjectIdentifier sm2sign_with_blake2b512 = sm_scheme.Branch("521");
        /// <summary>The object identifier <c>1.2.156.10197.1.522</c>.</summary>
        public static readonly DerObjectIdentifier sm2sign_with_blake2s256 = sm_scheme.Branch("522");
    }
}
