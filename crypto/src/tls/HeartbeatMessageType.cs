using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 6520 3.</summary>
    public abstract class HeartbeatMessageType
    {
        /// <summary>The <c>heartbeat_request</c> constant, with the value <c>1</c>.</summary>
        public const short heartbeat_request = 1;
        /// <summary>The <c>heartbeat_response</c> constant, with the value <c>2</c>.</summary>
        public const short heartbeat_response = 2;

        /// <summary>Get the name of the given heartbeat message type.</summary>
        /// <param name="heartbeatMessageType">The heartbeat message type.</param>
        /// <returns>The name.</returns>
        public static string GetName(short heartbeatMessageType)
        {
            switch (heartbeatMessageType)
            {
            case heartbeat_request:
                return "heartbeat_request";
            case heartbeat_response:
                return "heartbeat_response";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given heartbeat message type, made up of its name and its numeric value.
        /// </summary>
        /// <param name="heartbeatMessageType">The heartbeat message type.</param>
        /// <returns>The text.</returns>
        public static string GetText(short heartbeatMessageType)
        {
            return GetName(heartbeatMessageType) + "(" + heartbeatMessageType + ")";
        }

        /// <summary>Determine whether the given heartbeat message type is a valid value.</summary>
        /// <param name="heartbeatMessageType">The heartbeat message type.</param>
        /// <returns>true if the value is valid, false otherwise.</returns>
        public static bool IsValid(short heartbeatMessageType)
        {
            return heartbeatMessageType >= heartbeat_request && heartbeatMessageType <= heartbeat_response;
        }
    }
}
