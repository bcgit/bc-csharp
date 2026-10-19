using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Constants for the PSK key exchange modes of TLS 1.3.</summary>
    public abstract class PskKeyExchangeMode
    {
        /*
         * RFC 8446
         */

        /// <summary>The <c>psk_ke</c> constant, with the value <c>0</c>.</summary>
        public const short psk_ke = 0;
        /// <summary>The <c>psk_dhe_ke</c> constant, with the value <c>1</c>.</summary>
        public const short psk_dhe_ke = 1;

        public static string GetName(short pskKeyExchangeMode)
        {
            switch (pskKeyExchangeMode)
            {
            case psk_ke:
                return "psk_ke";
            case psk_dhe_ke:
                return "psk_dhe_ke";
            default:
                return "UNKNOWN";
            }
        }

        public static string GetText(short pskKeyExchangeMode)
        {
            return GetName(pskKeyExchangeMode) + "(" + pskKeyExchangeMode + ")";
        }

        public static bool IsRecognized(short pskKeyExchangeMode)
        {
            switch (pskKeyExchangeMode)
            {
            case psk_ke:
            case psk_dhe_ke:
                return true;
            default:
                return false;
            }
        }
    }
}
