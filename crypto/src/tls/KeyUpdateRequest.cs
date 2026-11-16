using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 8446 4.6.3</summary>
    public abstract class KeyUpdateRequest
    {
        /// <summary>The <c>update_not_requested</c> constant, with the value <c>0</c>.</summary>
        public const short update_not_requested = 0;
        /// <summary>The <c>update_requested</c> constant, with the value <c>1</c>.</summary>
        public const short update_requested = 1;

        /// <summary>Get the name of the given key update request.</summary>
        /// <param name="keyUpdateRequest">The key update request.</param>
        /// <returns>The name.</returns>
        public static string GetName(short keyUpdateRequest)
        {
            switch (keyUpdateRequest)
            {
            case update_not_requested:
                return "update_not_requested";
            case update_requested:
                return "update_requested";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given key update request, made up of its name and its numeric value.
        /// </summary>
        /// <param name="keyUpdateRequest">The key update request.</param>
        /// <returns>The text.</returns>
        public static string GetText(short keyUpdateRequest)
        {
            return GetName(keyUpdateRequest) + "(" + keyUpdateRequest + ")";
        }

        /// <summary>Determine whether the given key update request is a valid value.</summary>
        /// <param name="keyUpdateRequest">The key update request.</param>
        /// <returns>true if the value is valid, false otherwise.</returns>
        public static bool IsValid(short keyUpdateRequest)
        {
            return keyUpdateRequest >= update_not_requested && keyUpdateRequest <= update_requested;
        }
    }
}
