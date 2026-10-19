using System;

namespace Org.BouncyCastle.Tls
{
    public abstract class ClientCertificateType
    {
        /*
         *  RFC 4346 7.4.4
         */
        public const short rsa_sign = 1;
        /// <summary>The <c>dss_sign</c> constant, with the value <c>2</c>.</summary>
        public const short dss_sign = 2;
        /// <summary>The <c>rsa_fixed_dh</c> constant, with the value <c>3</c>.</summary>
        public const short rsa_fixed_dh = 3;
        /// <summary>The <c>dss_fixed_dh</c> constant, with the value <c>4</c>.</summary>
        public const short dss_fixed_dh = 4;
        /// <summary>The <c>rsa_ephemeral_dh_RESERVED</c> constant, with the value <c>5</c>.</summary>
        public const short rsa_ephemeral_dh_RESERVED = 5;
        /// <summary>The <c>dss_ephemeral_dh_RESERVED</c> constant, with the value <c>6</c>.</summary>
        public const short dss_ephemeral_dh_RESERVED = 6;
        /// <summary>The <c>fortezza_dms_RESERVED</c> constant, with the value <c>20</c>.</summary>
        public const short fortezza_dms_RESERVED = 20;

        /*
         * RFC 4492 5.5
         */
        public const short ecdsa_sign = 64;
        /// <summary>The <c>rsa_fixed_ecdh</c> constant, with the value <c>65</c>.</summary>
        public const short rsa_fixed_ecdh = 65;
        /// <summary>The <c>ecdsa_fixed_ecdh</c> constant, with the value <c>66</c>.</summary>
        public const short ecdsa_fixed_ecdh = 66;

        /*
         * RFC 9189
         */
        public const short gost_sign256 = 67;
        /// <summary>The <c>gost_sign512</c> constant, with the value <c>68</c>.</summary>
        public const short gost_sign512 = 68;

        public static string GetName(short clientCertificateType)
        {
            switch (clientCertificateType)
            {
            case rsa_sign:
                return "rsa_sign";
            case dss_sign:
                return "dss_sign";
            case rsa_fixed_dh:
                return "rsa_fixed_dh";
            case dss_fixed_dh:
                return "dss_fixed_dh";
            case rsa_ephemeral_dh_RESERVED:
                return "rsa_ephemeral_dh_RESERVED";
            case dss_ephemeral_dh_RESERVED:
                return "dss_ephemeral_dh_RESERVED";
            case fortezza_dms_RESERVED:
                return "fortezza_dms_RESERVED";
            case ecdsa_sign:
                return "ecdsa_sign";
            case rsa_fixed_ecdh:
                return "rsa_fixed_ecdh";
            case ecdsa_fixed_ecdh:
                return "ecdsa_fixed_ecdh";
            case gost_sign256:
                return "gost_sign256";
            case gost_sign512:
                return "gost_sign512";
            default:
                return "UNKNOWN";
            }
        }

        public static string GetText(short clientCertificateType)
        {
            return GetName(clientCertificateType) + "(" + clientCertificateType + ")";
        }
    }
}
