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

        /// <summary>Get the name of the given psk key exchange mode.</summary>
        /// <param name="pskKeyExchangeMode">The psk key exchange mode.</param>
        /// <returns>The name.</returns>
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

        /// <summary>
        /// Get a textual representation of the given psk key exchange mode, made up of its name and its numeric value.
        /// </summary>
        /// <param name="pskKeyExchangeMode">The psk key exchange mode.</param>
        /// <returns>The text.</returns>
        public static string GetText(short pskKeyExchangeMode)
        {
            return GetName(pskKeyExchangeMode) + "(" + pskKeyExchangeMode + ")";
        }

        /// <summary>Determine whether the given psk key exchange mode is a recognized value.</summary>
        /// <param name="pskKeyExchangeMode">The psk key exchange mode.</param>
        /// <returns>true if the value is recognized, false otherwise.</returns>
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
