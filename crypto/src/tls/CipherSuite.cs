using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 2246 A.5</summary>
    public abstract class CipherSuite
    {
        public static bool IsScsv(int cipherSuite)
        {
            switch (cipherSuite)
            {
            case TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
            case TLS_FALLBACK_SCSV:
                return true;
            default:
                return false;
            }
        }

        /// <summary>The <c>TLS_NULL_WITH_NULL_NULL</c> constant, with the value <c>0x0000</c>.</summary>
        public const int TLS_NULL_WITH_NULL_NULL = 0x0000;
        /// <summary>The <c>TLS_RSA_WITH_NULL_MD5</c> constant, with the value <c>0x0001</c>.</summary>
        public const int TLS_RSA_WITH_NULL_MD5 = 0x0001;
        /// <summary>The <c>TLS_RSA_WITH_NULL_SHA</c> constant, with the value <c>0x0002</c>.</summary>
        public const int TLS_RSA_WITH_NULL_SHA = 0x0002;
        /// <summary>The <c>TLS_RSA_EXPORT_WITH_RC4_40_MD5</c> constant, with the value <c>0x0003</c>.</summary>
        public const int TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003;
        /// <summary>The <c>TLS_RSA_WITH_RC4_128_MD5</c> constant, with the value <c>0x0004</c>.</summary>
        public const int TLS_RSA_WITH_RC4_128_MD5 = 0x0004;
        /// <summary>The <c>TLS_RSA_WITH_RC4_128_SHA</c> constant, with the value <c>0x0005</c>.</summary>
        public const int TLS_RSA_WITH_RC4_128_SHA = 0x0005;
        /// <summary>The <c>TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5</c> constant, with the value <c>0x0006</c>.</summary>
        public const int TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006;
        /// <summary>The <c>TLS_RSA_WITH_IDEA_CBC_SHA</c> constant, with the value <c>0x0007</c>.</summary>
        public const int TLS_RSA_WITH_IDEA_CBC_SHA = 0x0007;
        /// <summary>The <c>TLS_RSA_EXPORT_WITH_DES40_CBC_SHA</c> constant, with the value <c>0x0008</c>.</summary>
        public const int TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008;
        /// <summary>The <c>TLS_RSA_WITH_DES_CBC_SHA</c> constant, with the value <c>0x0009</c>.</summary>
        public const int TLS_RSA_WITH_DES_CBC_SHA = 0x0009;
        /// <summary>The <c>TLS_RSA_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0x000A</c>.</summary>
        public const int TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A;
        /// <summary>The <c>TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA</c> constant, with the value <c>0x000B</c>.</summary>
        public const int TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x000B;
        /// <summary>The <c>TLS_DH_DSS_WITH_DES_CBC_SHA</c> constant, with the value <c>0x000C</c>.</summary>
        public const int TLS_DH_DSS_WITH_DES_CBC_SHA = 0x000C;
        /// <summary>The <c>TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0x000D</c>.</summary>
        public const int TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000D;
        /// <summary>The <c>TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA</c> constant, with the value <c>0x000E</c>.</summary>
        public const int TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x000E;
        /// <summary>The <c>TLS_DH_RSA_WITH_DES_CBC_SHA</c> constant, with the value <c>0x000F</c>.</summary>
        public const int TLS_DH_RSA_WITH_DES_CBC_SHA = 0x000F;
        /// <summary>The <c>TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0x0010</c>.</summary>
        public const int TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010;
        /// <summary>The <c>TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA</c> constant, with the value <c>0x0011</c>.</summary>
        public const int TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011;
        /// <summary>The <c>TLS_DHE_DSS_WITH_DES_CBC_SHA</c> constant, with the value <c>0x0012</c>.</summary>
        public const int TLS_DHE_DSS_WITH_DES_CBC_SHA = 0x0012;
        /// <summary>The <c>TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0x0013</c>.</summary>
        public const int TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013;
        /// <summary>The <c>TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA</c> constant, with the value <c>0x0014</c>.</summary>
        public const int TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014;
        /// <summary>The <c>TLS_DHE_RSA_WITH_DES_CBC_SHA</c> constant, with the value <c>0x0015</c>.</summary>
        public const int TLS_DHE_RSA_WITH_DES_CBC_SHA = 0x0015;
        /// <summary>The <c>TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0x0016</c>.</summary>
        public const int TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016;
        /// <summary>The <c>TLS_DH_anon_EXPORT_WITH_RC4_40_MD5</c> constant, with the value <c>0x0017</c>.</summary>
        public const int TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = 0x0017;
        /// <summary>The <c>TLS_DH_anon_WITH_RC4_128_MD5</c> constant, with the value <c>0x0018</c>.</summary>
        public const int TLS_DH_anon_WITH_RC4_128_MD5 = 0x0018;
        /// <summary>The <c>TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA</c> constant, with the value <c>0x0019</c>.</summary>
        public const int TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019;
        /// <summary>The <c>TLS_DH_anon_WITH_DES_CBC_SHA</c> constant, with the value <c>0x001A</c>.</summary>
        public const int TLS_DH_anon_WITH_DES_CBC_SHA = 0x001A;
        /// <summary>The <c>TLS_DH_anon_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0x001B</c>.</summary>
        public const int TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B;

        /*
         * Note: The cipher suite values { 0x00, 0x1C } and { 0x00, 0x1D } are reserved to avoid
         * collision with Fortezza-based cipher suites in SSL 3.
         */

        /*
         * RFC 3268
         */
        public const int TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F;
        /// <summary>The <c>TLS_DH_DSS_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0x0030</c>.</summary>
        public const int TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x0030;
        /// <summary>The <c>TLS_DH_RSA_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0x0031</c>.</summary>
        public const int TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031;
        /// <summary>The <c>TLS_DHE_DSS_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0x0032</c>.</summary>
        public const int TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032;
        /// <summary>The <c>TLS_DHE_RSA_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0x0033</c>.</summary>
        public const int TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033;
        /// <summary>The <c>TLS_DH_anon_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0x0034</c>.</summary>
        public const int TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x0034;
        /// <summary>The <c>TLS_RSA_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0x0035</c>.</summary>
        public const int TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035;
        /// <summary>The <c>TLS_DH_DSS_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0x0036</c>.</summary>
        public const int TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x0036;
        /// <summary>The <c>TLS_DH_RSA_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0x0037</c>.</summary>
        public const int TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037;
        /// <summary>The <c>TLS_DHE_DSS_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0x0038</c>.</summary>
        public const int TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038;
        /// <summary>The <c>TLS_DHE_RSA_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0x0039</c>.</summary>
        public const int TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039;
        /// <summary>The <c>TLS_DH_anon_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0x003A</c>.</summary>
        public const int TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x003A;

        /*
         * RFC 5932
         */
        public const int TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0041;
        /// <summary>The <c>TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA</c> constant, with the value <c>0x0042</c>.</summary>
        public const int TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0042;
        /// <summary>The <c>TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA</c> constant, with the value <c>0x0043</c>.</summary>
        public const int TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0043;
        /// <summary>The <c>TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA</c> constant, with the value <c>0x0044</c>.</summary>
        public const int TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0044;
        /// <summary>The <c>TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA</c> constant, with the value <c>0x0045</c>.</summary>
        public const int TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0045;
        /// <summary>The <c>TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA</c> constant, with the value <c>0x0046</c>.</summary>
        public const int TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = 0x0046;

        /// <summary>The <c>TLS_RSA_WITH_CAMELLIA_256_CBC_SHA</c> constant, with the value <c>0x0084</c>.</summary>
        public const int TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084;
        /// <summary>The <c>TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA</c> constant, with the value <c>0x0085</c>.</summary>
        public const int TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0085;
        /// <summary>The <c>TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA</c> constant, with the value <c>0x0086</c>.</summary>
        public const int TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0086;
        /// <summary>The <c>TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA</c> constant, with the value <c>0x0087</c>.</summary>
        public const int TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0087;
        /// <summary>The <c>TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA</c> constant, with the value <c>0x0088</c>.</summary>
        public const int TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088;
        /// <summary>The <c>TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA</c> constant, with the value <c>0x0089</c>.</summary>
        public const int TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = 0x0089;

        /// <summary>The <c>TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0x00BA</c>.</summary>
        public const int TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BA;
        /// <summary>
        /// The <c>TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0x00BB</c>.
        /// </summary>
        public const int TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BB;
        /// <summary>
        /// The <c>TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0x00BC</c>.
        /// </summary>
        public const int TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BC;
        /// <summary>
        /// The <c>TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0x00BD</c>.
        /// </summary>
        public const int TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BD;
        /// <summary>
        /// The <c>TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0x00BE</c>.
        /// </summary>
        public const int TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BE;
        /// <summary>
        /// The <c>TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0x00BF</c>.
        /// </summary>
        public const int TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BF;

        /// <summary>The <c>TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256</c> constant, with the value <c>0x00C0</c>.</summary>
        public const int TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C0;
        /// <summary>
        /// The <c>TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256</c> constant, with the value <c>0x00C1</c>.
        /// </summary>
        public const int TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C1;
        /// <summary>
        /// The <c>TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256</c> constant, with the value <c>0x00C2</c>.
        /// </summary>
        public const int TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C2;
        /// <summary>
        /// The <c>TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256</c> constant, with the value <c>0x00C3</c>.
        /// </summary>
        public const int TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C3;
        /// <summary>
        /// The <c>TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256</c> constant, with the value <c>0x00C4</c>.
        /// </summary>
        public const int TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C4;
        /// <summary>
        /// The <c>TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256</c> constant, with the value <c>0x00C5</c>.
        /// </summary>
        public const int TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C5;

        /*
         * RFC 4162
         */
        public const int TLS_RSA_WITH_SEED_CBC_SHA = 0x0096;
        /// <summary>The <c>TLS_DH_DSS_WITH_SEED_CBC_SHA</c> constant, with the value <c>0x0097</c>.</summary>
        public const int TLS_DH_DSS_WITH_SEED_CBC_SHA = 0x0097;
        /// <summary>The <c>TLS_DH_RSA_WITH_SEED_CBC_SHA</c> constant, with the value <c>0x0098</c>.</summary>
        public const int TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x0098;
        /// <summary>The <c>TLS_DHE_DSS_WITH_SEED_CBC_SHA</c> constant, with the value <c>0x0099</c>.</summary>
        public const int TLS_DHE_DSS_WITH_SEED_CBC_SHA = 0x0099;
        /// <summary>The <c>TLS_DHE_RSA_WITH_SEED_CBC_SHA</c> constant, with the value <c>0x009A</c>.</summary>
        public const int TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x009A;
        /// <summary>The <c>TLS_DH_anon_WITH_SEED_CBC_SHA</c> constant, with the value <c>0x009B</c>.</summary>
        public const int TLS_DH_anon_WITH_SEED_CBC_SHA = 0x009B;

        /*
         * RFC 4279
         */
        public const int TLS_PSK_WITH_RC4_128_SHA = 0x008A;
        /// <summary>The <c>TLS_PSK_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0x008B</c>.</summary>
        public const int TLS_PSK_WITH_3DES_EDE_CBC_SHA = 0x008B;
        /// <summary>The <c>TLS_PSK_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0x008C</c>.</summary>
        public const int TLS_PSK_WITH_AES_128_CBC_SHA = 0x008C;
        /// <summary>The <c>TLS_PSK_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0x008D</c>.</summary>
        public const int TLS_PSK_WITH_AES_256_CBC_SHA = 0x008D;
        /// <summary>The <c>TLS_DHE_PSK_WITH_RC4_128_SHA</c> constant, with the value <c>0x008E</c>.</summary>
        public const int TLS_DHE_PSK_WITH_RC4_128_SHA = 0x008E;
        /// <summary>The <c>TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0x008F</c>.</summary>
        public const int TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = 0x008F;
        /// <summary>The <c>TLS_DHE_PSK_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0x0090</c>.</summary>
        public const int TLS_DHE_PSK_WITH_AES_128_CBC_SHA = 0x0090;
        /// <summary>The <c>TLS_DHE_PSK_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0x0091</c>.</summary>
        public const int TLS_DHE_PSK_WITH_AES_256_CBC_SHA = 0x0091;
        /// <summary>The <c>TLS_RSA_PSK_WITH_RC4_128_SHA</c> constant, with the value <c>0x0092</c>.</summary>
        public const int TLS_RSA_PSK_WITH_RC4_128_SHA = 0x0092;
        /// <summary>The <c>TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0x0093</c>.</summary>
        public const int TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = 0x0093;
        /// <summary>The <c>TLS_RSA_PSK_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0x0094</c>.</summary>
        public const int TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0x0094;
        /// <summary>The <c>TLS_RSA_PSK_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0x0095</c>.</summary>
        public const int TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0x0095;

        /*
         * RFC 4492
         */
        public const int TLS_ECDH_ECDSA_WITH_NULL_SHA = 0xC001;
        /// <summary>The <c>TLS_ECDH_ECDSA_WITH_RC4_128_SHA</c> constant, with the value <c>0xC002</c>.</summary>
        public const int TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xC002;
        /// <summary>The <c>TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0xC003</c>.</summary>
        public const int TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC003;
        /// <summary>The <c>TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0xC004</c>.</summary>
        public const int TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xC004;
        /// <summary>The <c>TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0xC005</c>.</summary>
        public const int TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xC005;
        /// <summary>The <c>TLS_ECDHE_ECDSA_WITH_NULL_SHA</c> constant, with the value <c>0xC006</c>.</summary>
        public const int TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xC006;
        /// <summary>The <c>TLS_ECDHE_ECDSA_WITH_RC4_128_SHA</c> constant, with the value <c>0xC007</c>.</summary>
        public const int TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xC007;
        /// <summary>The <c>TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0xC008</c>.</summary>
        public const int TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008;
        /// <summary>The <c>TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0xC009</c>.</summary>
        public const int TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009;
        /// <summary>The <c>TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0xC00A</c>.</summary>
        public const int TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_NULL_SHA</c> constant, with the value <c>0xC00B</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_NULL_SHA = 0xC00B;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_RC4_128_SHA</c> constant, with the value <c>0xC00C</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xC00C;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0xC00D</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xC00D;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0xC00E</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xC00E;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0xC00F</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xC00F;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_NULL_SHA</c> constant, with the value <c>0xC010</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_NULL_SHA = 0xC010;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_RC4_128_SHA</c> constant, with the value <c>0xC011</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xC011;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0xC012</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0xC013</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0xC014</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014;
        /// <summary>The <c>TLS_ECDH_anon_WITH_NULL_SHA</c> constant, with the value <c>0xC015</c>.</summary>
        public const int TLS_ECDH_anon_WITH_NULL_SHA = 0xC015;
        /// <summary>The <c>TLS_ECDH_anon_WITH_RC4_128_SHA</c> constant, with the value <c>0xC016</c>.</summary>
        public const int TLS_ECDH_anon_WITH_RC4_128_SHA = 0xC016;
        /// <summary>The <c>TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0xC017</c>.</summary>
        public const int TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = 0xC017;
        /// <summary>The <c>TLS_ECDH_anon_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0xC018</c>.</summary>
        public const int TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 0xC018;
        /// <summary>The <c>TLS_ECDH_anon_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0xC019</c>.</summary>
        public const int TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 0xC019;

        /*
         * RFC 4785
         */
        public const int TLS_PSK_WITH_NULL_SHA = 0x002C;
        /// <summary>The <c>TLS_DHE_PSK_WITH_NULL_SHA</c> constant, with the value <c>0x002D</c>.</summary>
        public const int TLS_DHE_PSK_WITH_NULL_SHA = 0x002D;
        /// <summary>The <c>TLS_RSA_PSK_WITH_NULL_SHA</c> constant, with the value <c>0x002E</c>.</summary>
        public const int TLS_RSA_PSK_WITH_NULL_SHA = 0x002E;

        /*
         * RFC 5054
         */
        public const int TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0xC01A;
        /// <summary>The <c>TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0xC01B</c>.</summary>
        public const int TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xC01B;
        /// <summary>The <c>TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0xC01C</c>.</summary>
        public const int TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0xC01C;
        /// <summary>The <c>TLS_SRP_SHA_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0xC01D</c>.</summary>
        public const int TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D;
        /// <summary>The <c>TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0xC01E</c>.</summary>
        public const int TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E;
        /// <summary>The <c>TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0xC01F</c>.</summary>
        public const int TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0xC01F;
        /// <summary>The <c>TLS_SRP_SHA_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0xC020</c>.</summary>
        public const int TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020;
        /// <summary>The <c>TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0xC021</c>.</summary>
        public const int TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021;
        /// <summary>The <c>TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0xC022</c>.</summary>
        public const int TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xC022;

        /*
         * RFC 5246
         */
        public const int TLS_RSA_WITH_NULL_SHA256 = 0x003B;
        /// <summary>The <c>TLS_RSA_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0x003C</c>.</summary>
        public const int TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C;
        /// <summary>The <c>TLS_RSA_WITH_AES_256_CBC_SHA256</c> constant, with the value <c>0x003D</c>.</summary>
        public const int TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D;
        /// <summary>The <c>TLS_DH_DSS_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0x003E</c>.</summary>
        public const int TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x003E;
        /// <summary>The <c>TLS_DH_RSA_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0x003F</c>.</summary>
        public const int TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003F;
        /// <summary>The <c>TLS_DHE_DSS_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0x0040</c>.</summary>
        public const int TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040;
        /// <summary>The <c>TLS_DHE_RSA_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0x0067</c>.</summary>
        public const int TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067;
        /// <summary>The <c>TLS_DH_DSS_WITH_AES_256_CBC_SHA256</c> constant, with the value <c>0x0068</c>.</summary>
        public const int TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x0068;
        /// <summary>The <c>TLS_DH_RSA_WITH_AES_256_CBC_SHA256</c> constant, with the value <c>0x0069</c>.</summary>
        public const int TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069;
        /// <summary>The <c>TLS_DHE_DSS_WITH_AES_256_CBC_SHA256</c> constant, with the value <c>0x006A</c>.</summary>
        public const int TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006A;
        /// <summary>The <c>TLS_DHE_RSA_WITH_AES_256_CBC_SHA256</c> constant, with the value <c>0x006B</c>.</summary>
        public const int TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B;
        /// <summary>The <c>TLS_DH_anon_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0x006C</c>.</summary>
        public const int TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x006C;
        /// <summary>The <c>TLS_DH_anon_WITH_AES_256_CBC_SHA256</c> constant, with the value <c>0x006D</c>.</summary>
        public const int TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x006D;

        /*
         * RFC 5288
         */
        public const int TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C;
        /// <summary>The <c>TLS_RSA_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0x009D</c>.</summary>
        public const int TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D;
        /// <summary>The <c>TLS_DHE_RSA_WITH_AES_128_GCM_SHA256</c> constant, with the value <c>0x009E</c>.</summary>
        public const int TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E;
        /// <summary>The <c>TLS_DHE_RSA_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0x009F</c>.</summary>
        public const int TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F;
        /// <summary>The <c>TLS_DH_RSA_WITH_AES_128_GCM_SHA256</c> constant, with the value <c>0x00A0</c>.</summary>
        public const int TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00A0;
        /// <summary>The <c>TLS_DH_RSA_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0x00A1</c>.</summary>
        public const int TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00A1;
        /// <summary>The <c>TLS_DHE_DSS_WITH_AES_128_GCM_SHA256</c> constant, with the value <c>0x00A2</c>.</summary>
        public const int TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x00A2;
        /// <summary>The <c>TLS_DHE_DSS_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0x00A3</c>.</summary>
        public const int TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x00A3;
        /// <summary>The <c>TLS_DH_DSS_WITH_AES_128_GCM_SHA256</c> constant, with the value <c>0x00A4</c>.</summary>
        public const int TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = 0x00A4;
        /// <summary>The <c>TLS_DH_DSS_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0x00A5</c>.</summary>
        public const int TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = 0x00A5;
        /// <summary>The <c>TLS_DH_anon_WITH_AES_128_GCM_SHA256</c> constant, with the value <c>0x00A6</c>.</summary>
        public const int TLS_DH_anon_WITH_AES_128_GCM_SHA256 = 0x00A6;
        /// <summary>The <c>TLS_DH_anon_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0x00A7</c>.</summary>
        public const int TLS_DH_anon_WITH_AES_256_GCM_SHA384 = 0x00A7;

        /*
         * RFC 5289
         */
        public const int TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023;
        /// <summary>
        /// The <c>TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384</c> constant, with the value <c>0xC024</c>.
        /// </summary>
        public const int TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024;
        /// <summary>The <c>TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0xC025</c>.</summary>
        public const int TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC025;
        /// <summary>The <c>TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384</c> constant, with the value <c>0xC026</c>.</summary>
        public const int TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC026;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0xC027</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384</c> constant, with the value <c>0xC028</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0xC029</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xC029;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384</c> constant, with the value <c>0xC02A</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xC02A;
        /// <summary>
        /// The <c>TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256</c> constant, with the value <c>0xC02B</c>.
        /// </summary>
        public const int TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B;
        /// <summary>
        /// The <c>TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0xC02C</c>.
        /// </summary>
        public const int TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C;
        /// <summary>The <c>TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256</c> constant, with the value <c>0xC02D</c>.</summary>
        public const int TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02D;
        /// <summary>The <c>TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0xC02E</c>.</summary>
        public const int TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02E;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</c> constant, with the value <c>0xC02F</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0xC030</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256</c> constant, with the value <c>0xC031</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xC031;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0xC032</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xC032;

        /*
         * RFC 5487
         */
        public const int TLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00A8;
        /// <summary>The <c>TLS_PSK_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0x00A9</c>.</summary>
        public const int TLS_PSK_WITH_AES_256_GCM_SHA384 = 0x00A9;
        /// <summary>The <c>TLS_DHE_PSK_WITH_AES_128_GCM_SHA256</c> constant, with the value <c>0x00AA</c>.</summary>
        public const int TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00AA;
        /// <summary>The <c>TLS_DHE_PSK_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0x00AB</c>.</summary>
        public const int TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00AB;
        /// <summary>The <c>TLS_RSA_PSK_WITH_AES_128_GCM_SHA256</c> constant, with the value <c>0x00AC</c>.</summary>
        public const int TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 0x00AC;
        /// <summary>The <c>TLS_RSA_PSK_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0x00AD</c>.</summary>
        public const int TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 0x00AD;
        /// <summary>The <c>TLS_PSK_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0x00AE</c>.</summary>
        public const int TLS_PSK_WITH_AES_128_CBC_SHA256 = 0x00AE;
        /// <summary>The <c>TLS_PSK_WITH_AES_256_CBC_SHA384</c> constant, with the value <c>0x00AF</c>.</summary>
        public const int TLS_PSK_WITH_AES_256_CBC_SHA384 = 0x00AF;
        /// <summary>The <c>TLS_PSK_WITH_NULL_SHA256</c> constant, with the value <c>0x00B0</c>.</summary>
        public const int TLS_PSK_WITH_NULL_SHA256 = 0x00B0;
        /// <summary>The <c>TLS_PSK_WITH_NULL_SHA384</c> constant, with the value <c>0x00B1</c>.</summary>
        public const int TLS_PSK_WITH_NULL_SHA384 = 0x00B1;
        /// <summary>The <c>TLS_DHE_PSK_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0x00B2</c>.</summary>
        public const int TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0x00B2;
        /// <summary>The <c>TLS_DHE_PSK_WITH_AES_256_CBC_SHA384</c> constant, with the value <c>0x00B3</c>.</summary>
        public const int TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0x00B3;
        /// <summary>The <c>TLS_DHE_PSK_WITH_NULL_SHA256</c> constant, with the value <c>0x00B4</c>.</summary>
        public const int TLS_DHE_PSK_WITH_NULL_SHA256 = 0x00B4;
        /// <summary>The <c>TLS_DHE_PSK_WITH_NULL_SHA384</c> constant, with the value <c>0x00B5</c>.</summary>
        public const int TLS_DHE_PSK_WITH_NULL_SHA384 = 0x00B5;
        /// <summary>The <c>TLS_RSA_PSK_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0x00B6</c>.</summary>
        public const int TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 0x00B6;
        /// <summary>The <c>TLS_RSA_PSK_WITH_AES_256_CBC_SHA384</c> constant, with the value <c>0x00B7</c>.</summary>
        public const int TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 0x00B7;
        /// <summary>The <c>TLS_RSA_PSK_WITH_NULL_SHA256</c> constant, with the value <c>0x00B8</c>.</summary>
        public const int TLS_RSA_PSK_WITH_NULL_SHA256 = 0x00B8;
        /// <summary>The <c>TLS_RSA_PSK_WITH_NULL_SHA384</c> constant, with the value <c>0x00B9</c>.</summary>
        public const int TLS_RSA_PSK_WITH_NULL_SHA384 = 0x00B9;

        /*
         * RFC 5489
         */
        public const int TLS_ECDHE_PSK_WITH_RC4_128_SHA = 0xC033;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA</c> constant, with the value <c>0xC034</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = 0xC034;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA</c> constant, with the value <c>0xC035</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 0xC035;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA</c> constant, with the value <c>0xC036</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 0xC036;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256</c> constant, with the value <c>0xC037</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xC037;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384</c> constant, with the value <c>0xC038</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 0xC038;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_NULL_SHA</c> constant, with the value <c>0xC039</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_NULL_SHA = 0xC039;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_NULL_SHA256</c> constant, with the value <c>0xC03A</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_NULL_SHA256 = 0xC03A;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_NULL_SHA384</c> constant, with the value <c>0xC03B</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_NULL_SHA384 = 0xC03B;

        /*
         * RFC 5746
         */
        public const int TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF;

        /*
         * RFC 6209
         */
        public const int TLS_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC03C;
        /// <summary>The <c>TLS_RSA_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC03D</c>.</summary>
        public const int TLS_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC03D;
        /// <summary>The <c>TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC03E</c>.</summary>
        public const int TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC03E;
        /// <summary>The <c>TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC03F</c>.</summary>
        public const int TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC03F;
        /// <summary>The <c>TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC040</c>.</summary>
        public const int TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC040;
        /// <summary>The <c>TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC041</c>.</summary>
        public const int TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC041;
        /// <summary>The <c>TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC042</c>.</summary>
        public const int TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC042;
        /// <summary>The <c>TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC043</c>.</summary>
        public const int TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC043;
        /// <summary>The <c>TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC044</c>.</summary>
        public const int TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC044;
        /// <summary>The <c>TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC045</c>.</summary>
        public const int TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC045;
        /// <summary>The <c>TLS_DH_anon_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC046</c>.</summary>
        public const int TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = 0xC046;
        /// <summary>The <c>TLS_DH_anon_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC047</c>.</summary>
        public const int TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = 0xC047;

        /// <summary>
        /// The <c>TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC048</c>.
        /// </summary>
        public const int TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC048;
        /// <summary>
        /// The <c>TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC049</c>.
        /// </summary>
        public const int TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC049;
        /// <summary>
        /// The <c>TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC04A</c>.
        /// </summary>
        public const int TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC04A;
        /// <summary>
        /// The <c>TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC04B</c>.
        /// </summary>
        public const int TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC04B;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC04C</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04C;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC04D</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04D;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC04E</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04E;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC04F</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04F;

        /// <summary>The <c>TLS_RSA_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC050</c>.</summary>
        public const int TLS_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC050;
        /// <summary>The <c>TLS_RSA_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC051</c>.</summary>
        public const int TLS_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC051;
        /// <summary>The <c>TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC052</c>.</summary>
        public const int TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC052;
        /// <summary>The <c>TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC053</c>.</summary>
        public const int TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC053;
        /// <summary>The <c>TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC054</c>.</summary>
        public const int TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC054;
        /// <summary>The <c>TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC055</c>.</summary>
        public const int TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC055;
        /// <summary>The <c>TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC056</c>.</summary>
        public const int TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC056;
        /// <summary>The <c>TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC057</c>.</summary>
        public const int TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC057;
        /// <summary>The <c>TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC058</c>.</summary>
        public const int TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC058;
        /// <summary>The <c>TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC059</c>.</summary>
        public const int TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC059;
        /// <summary>The <c>TLS_DH_anon_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC05A</c>.</summary>
        public const int TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = 0xC05A;
        /// <summary>The <c>TLS_DH_anon_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC05B</c>.</summary>
        public const int TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = 0xC05B;

        /// <summary>
        /// The <c>TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC05C</c>.
        /// </summary>
        public const int TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05C;
        /// <summary>
        /// The <c>TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC05D</c>.
        /// </summary>
        public const int TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05D;
        /// <summary>
        /// The <c>TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC05E</c>.
        /// </summary>
        public const int TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05E;
        /// <summary>
        /// The <c>TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC05F</c>.
        /// </summary>
        public const int TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05F;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC060</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC060;
        /// <summary>The <c>TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC061</c>.</summary>
        public const int TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC061;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC062</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC062;
        /// <summary>The <c>TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC063</c>.</summary>
        public const int TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC063;

        /// <summary>The <c>TLS_PSK_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC064</c>.</summary>
        public const int TLS_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC064;
        /// <summary>The <c>TLS_PSK_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC065</c>.</summary>
        public const int TLS_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC065;
        /// <summary>The <c>TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC066</c>.</summary>
        public const int TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC066;
        /// <summary>The <c>TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC067</c>.</summary>
        public const int TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC067;
        /// <summary>The <c>TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC068</c>.</summary>
        public const int TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC068;
        /// <summary>The <c>TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC069</c>.</summary>
        public const int TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC069;
        /// <summary>The <c>TLS_PSK_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC06A</c>.</summary>
        public const int TLS_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06A;
        /// <summary>The <c>TLS_PSK_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC06B</c>.</summary>
        public const int TLS_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06B;
        /// <summary>The <c>TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC06C</c>.</summary>
        public const int TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06C;
        /// <summary>The <c>TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC06D</c>.</summary>
        public const int TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06D;
        /// <summary>The <c>TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256</c> constant, with the value <c>0xC06E</c>.</summary>
        public const int TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06E;
        /// <summary>The <c>TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384</c> constant, with the value <c>0xC06F</c>.</summary>
        public const int TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06F;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256</c> constant, with the value <c>0xC070</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC070;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384</c> constant, with the value <c>0xC071</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC071;

        /*
         * RFC 6367
         */
        public const int TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC072;
        /// <summary>
        /// The <c>TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384</c> constant, with the value <c>0xC073</c>.
        /// </summary>
        public const int TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC073;
        /// <summary>
        /// The <c>TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0xC074</c>.
        /// </summary>
        public const int TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC074;
        /// <summary>
        /// The <c>TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384</c> constant, with the value <c>0xC075</c>.
        /// </summary>
        public const int TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC075;
        /// <summary>
        /// The <c>TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0xC076</c>.
        /// </summary>
        public const int TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC076;
        /// <summary>
        /// The <c>TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384</c> constant, with the value <c>0xC077</c>.
        /// </summary>
        public const int TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC077;
        /// <summary>
        /// The <c>TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0xC078</c>.
        /// </summary>
        public const int TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC078;
        /// <summary>
        /// The <c>TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384</c> constant, with the value <c>0xC079</c>.
        /// </summary>
        public const int TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC079;

        /// <summary>The <c>TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC07A</c>.</summary>
        public const int TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07A;
        /// <summary>The <c>TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC07B</c>.</summary>
        public const int TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07B;
        /// <summary>
        /// The <c>TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC07C</c>.
        /// </summary>
        public const int TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07C;
        /// <summary>
        /// The <c>TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC07D</c>.
        /// </summary>
        public const int TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07D;
        /// <summary>
        /// The <c>TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC07E</c>.
        /// </summary>
        public const int TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07E;
        /// <summary>
        /// The <c>TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC07F</c>.
        /// </summary>
        public const int TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07F;
        /// <summary>
        /// The <c>TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC080</c>.
        /// </summary>
        public const int TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC080;
        /// <summary>
        /// The <c>TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC081</c>.
        /// </summary>
        public const int TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC081;
        /// <summary>
        /// The <c>TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC082</c>.
        /// </summary>
        public const int TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC082;
        /// <summary>
        /// The <c>TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC083</c>.
        /// </summary>
        public const int TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC083;
        /// <summary>
        /// The <c>TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC084</c>.
        /// </summary>
        public const int TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = 0xC084;
        /// <summary>
        /// The <c>TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC085</c>.
        /// </summary>
        public const int TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = 0xC085;
        /// <summary>
        /// The <c>TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC086</c>.
        /// </summary>
        public const int TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC086;
        /// <summary>
        /// The <c>TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC087</c>.
        /// </summary>
        public const int TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC087;
        /// <summary>
        /// The <c>TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC088</c>.
        /// </summary>
        public const int TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC088;
        /// <summary>
        /// The <c>TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC089</c>.
        /// </summary>
        public const int TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC089;
        /// <summary>
        /// The <c>TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC08A</c>.
        /// </summary>
        public const int TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08A;
        /// <summary>
        /// The <c>TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC08B</c>.
        /// </summary>
        public const int TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08B;
        /// <summary>
        /// The <c>TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC08C</c>.
        /// </summary>
        public const int TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08C;
        /// <summary>
        /// The <c>TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC08D</c>.
        /// </summary>
        public const int TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08D;

        /// <summary>The <c>TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC08E</c>.</summary>
        public const int TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08E;
        /// <summary>The <c>TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC08F</c>.</summary>
        public const int TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08F;
        /// <summary>
        /// The <c>TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC090</c>.
        /// </summary>
        public const int TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC090;
        /// <summary>
        /// The <c>TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC091</c>.
        /// </summary>
        public const int TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC091;
        /// <summary>
        /// The <c>TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256</c> constant, with the value <c>0xC092</c>.
        /// </summary>
        public const int TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC092;
        /// <summary>
        /// The <c>TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384</c> constant, with the value <c>0xC093</c>.
        /// </summary>
        public const int TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC093;
        /// <summary>The <c>TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0xC094</c>.</summary>
        public const int TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC094;
        /// <summary>The <c>TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384</c> constant, with the value <c>0xC095</c>.</summary>
        public const int TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC095;
        /// <summary>
        /// The <c>TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0xC096</c>.
        /// </summary>
        public const int TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC096;
        /// <summary>
        /// The <c>TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384</c> constant, with the value <c>0xC097</c>.
        /// </summary>
        public const int TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC097;
        /// <summary>
        /// The <c>TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0xC098</c>.
        /// </summary>
        public const int TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC098;
        /// <summary>
        /// The <c>TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384</c> constant, with the value <c>0xC099</c>.
        /// </summary>
        public const int TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC099;
        /// <summary>
        /// The <c>TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256</c> constant, with the value <c>0xC09A</c>.
        /// </summary>
        public const int TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC09A;
        /// <summary>
        /// The <c>TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384</c> constant, with the value <c>0xC09B</c>.
        /// </summary>
        public const int TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC09B;

        /*
         * RFC 6655
         */
        public const int TLS_RSA_WITH_AES_128_CCM = 0xC09C;
        /// <summary>The <c>TLS_RSA_WITH_AES_256_CCM</c> constant, with the value <c>0xC09D</c>.</summary>
        public const int TLS_RSA_WITH_AES_256_CCM = 0xC09D;
        /// <summary>The <c>TLS_DHE_RSA_WITH_AES_128_CCM</c> constant, with the value <c>0xC09E</c>.</summary>
        public const int TLS_DHE_RSA_WITH_AES_128_CCM = 0xC09E;
        /// <summary>The <c>TLS_DHE_RSA_WITH_AES_256_CCM</c> constant, with the value <c>0xC09F</c>.</summary>
        public const int TLS_DHE_RSA_WITH_AES_256_CCM = 0xC09F;
        /// <summary>The <c>TLS_RSA_WITH_AES_128_CCM_8</c> constant, with the value <c>0xC0A0</c>.</summary>
        public const int TLS_RSA_WITH_AES_128_CCM_8 = 0xC0A0;
        /// <summary>The <c>TLS_RSA_WITH_AES_256_CCM_8</c> constant, with the value <c>0xC0A1</c>.</summary>
        public const int TLS_RSA_WITH_AES_256_CCM_8 = 0xC0A1;
        /// <summary>The <c>TLS_DHE_RSA_WITH_AES_128_CCM_8</c> constant, with the value <c>0xC0A2</c>.</summary>
        public const int TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xC0A2;
        /// <summary>The <c>TLS_DHE_RSA_WITH_AES_256_CCM_8</c> constant, with the value <c>0xC0A3</c>.</summary>
        public const int TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xC0A3;
        /// <summary>The <c>TLS_PSK_WITH_AES_128_CCM</c> constant, with the value <c>0xC0A4</c>.</summary>
        public const int TLS_PSK_WITH_AES_128_CCM = 0xC0A4;
        /// <summary>The <c>TLS_PSK_WITH_AES_256_CCM</c> constant, with the value <c>0xC0A5</c>.</summary>
        public const int TLS_PSK_WITH_AES_256_CCM = 0xC0A5;
        /// <summary>The <c>TLS_DHE_PSK_WITH_AES_128_CCM</c> constant, with the value <c>0xC0A6</c>.</summary>
        public const int TLS_DHE_PSK_WITH_AES_128_CCM = 0xC0A6;
        /// <summary>The <c>TLS_DHE_PSK_WITH_AES_256_CCM</c> constant, with the value <c>0xC0A7</c>.</summary>
        public const int TLS_DHE_PSK_WITH_AES_256_CCM = 0xC0A7;
        /// <summary>The <c>TLS_PSK_WITH_AES_128_CCM_8</c> constant, with the value <c>0xC0A8</c>.</summary>
        public const int TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8;
        /// <summary>The <c>TLS_PSK_WITH_AES_256_CCM_8</c> constant, with the value <c>0xC0A9</c>.</summary>
        public const int TLS_PSK_WITH_AES_256_CCM_8 = 0xC0A9;
        /// <summary>The <c>TLS_PSK_DHE_WITH_AES_128_CCM_8</c> constant, with the value <c>0xC0AA</c>.</summary>
        public const int TLS_PSK_DHE_WITH_AES_128_CCM_8 = 0xC0AA;
        /// <summary>The <c>TLS_PSK_DHE_WITH_AES_256_CCM_8</c> constant, with the value <c>0xC0AB</c>.</summary>
        public const int TLS_PSK_DHE_WITH_AES_256_CCM_8 = 0xC0AB;

        /*
         * RFC 7251
         */
        public const int TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC;
        /// <summary>The <c>TLS_ECDHE_ECDSA_WITH_AES_256_CCM</c> constant, with the value <c>0xC0AD</c>.</summary>
        public const int TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xC0AD;
        /// <summary>The <c>TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8</c> constant, with the value <c>0xC0AE</c>.</summary>
        public const int TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE;
        /// <summary>The <c>TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8</c> constant, with the value <c>0xC0AF</c>.</summary>
        public const int TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xC0AF;

        /*
         * RFC 7507
         */
        public const int TLS_FALLBACK_SCSV = 0x5600;

        /*
         * RFC 7905
         */
        public const int TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8;
        /// <summary>
        /// The <c>TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256</c> constant, with the value <c>0xCCA9</c>.
        /// </summary>
        public const int TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9;
        /// <summary>
        /// The <c>TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256</c> constant, with the value <c>0xCCAA</c>.
        /// </summary>
        public const int TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAA;
        /// <summary>The <c>TLS_PSK_WITH_CHACHA20_POLY1305_SHA256</c> constant, with the value <c>0xCCAB</c>.</summary>
        public const int TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAB;
        /// <summary>
        /// The <c>TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256</c> constant, with the value <c>0xCCAC</c>.
        /// </summary>
        public const int TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAC;
        /// <summary>
        /// The <c>TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256</c> constant, with the value <c>0xCCAD</c>.
        /// </summary>
        public const int TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAD;
        /// <summary>
        /// The <c>TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256</c> constant, with the value <c>0xCCAE</c>.
        /// </summary>
        public const int TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xCCAE;

        /*
         * RFC 8442
         */
        public const int TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 = 0xD001;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384</c> constant, with the value <c>0xD002</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 = 0xD002;
        /// <summary>
        /// The <c>TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256</c> constant, with the value <c>0xD003</c>.
        /// </summary>
        public const int TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 = 0xD003;
        /// <summary>The <c>TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256</c> constant, with the value <c>0xD005</c>.</summary>
        public const int TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 = 0xD005;

        /*
         * TLS 1.3 Section
         *
         * Although TLS 1.3 uses the same cipher suite space as previous versions of TLS, TLS 1.3 cipher
         * suites are defined differently, only specifying the symmetric ciphers, and cannot be used for
         * TLS 1.2. Similarly, cipher suites for TLS 1.2 and lower cannot be used with TLS 1.3.
         */

        /*
         * RFC 8446
         */
        public const int TLS_AES_128_GCM_SHA256 = 0x1301;
        /// <summary>The <c>TLS_AES_256_GCM_SHA384</c> constant, with the value <c>0x1302</c>.</summary>
        public const int TLS_AES_256_GCM_SHA384 = 0x1302;
        /// <summary>The <c>TLS_CHACHA20_POLY1305_SHA256</c> constant, with the value <c>0x1303</c>.</summary>
        public const int TLS_CHACHA20_POLY1305_SHA256 = 0x1303;
        /// <summary>The <c>TLS_AES_128_CCM_SHA256</c> constant, with the value <c>0x1304</c>.</summary>
        public const int TLS_AES_128_CCM_SHA256 = 0x1304;
        /// <summary>The <c>TLS_AES_128_CCM_8_SHA256</c> constant, with the value <c>0x1305</c>.</summary>
        public const int TLS_AES_128_CCM_8_SHA256 = 0x1305;

        /*
         * RFC 8998
         */
        public const int TLS_SM4_GCM_SM3 = 0x00C6;
        /// <summary>The <c>TLS_SM4_CCM_SM3</c> constant, with the value <c>0x00C7</c>.</summary>
        public const int TLS_SM4_CCM_SM3 = 0x00C7;

        /*
         * RFC 9150
         */
        public const int TLS_SHA256_SHA256 = 0xC0B4;
        /// <summary>The <c>TLS_SHA384_SHA384</c> constant, with the value <c>0xC0B5</c>.</summary>
        public const int TLS_SHA384_SHA384 = 0xC0B5;

        /*
         * RFC 9189
         */
        public const int TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC = 0xC100;
        /// <summary>
        /// The <c>TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC</c> constant, with the value <c>0xC101</c>.
        /// </summary>
        public const int TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC = 0xC101;
        /// <summary>
        /// The <c>TLS_GOSTR341112_256_WITH_28147_CNT_IMIT</c> constant, with the value <c>0xC102</c>.
        /// </summary>
        public const int TLS_GOSTR341112_256_WITH_28147_CNT_IMIT = 0xC102;
    }
}
