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

        public static string GetText(short heartbeatMessageType)
        {
            return GetName(heartbeatMessageType) + "(" + heartbeatMessageType + ")";
        }

        public static bool IsValid(short heartbeatMessageType)
        {
            return heartbeatMessageType >= heartbeat_request && heartbeatMessageType <= heartbeat_response;
        }
    }
}
