using System;

namespace Org.BouncyCastle.Tls
{
    /*
     * RFC 6520
     */
    public abstract class HeartbeatMode
    {
        /// <summary>The <c>peer_allowed_to_send</c> constant, with the value <c>1</c>.</summary>
        public const short peer_allowed_to_send = 1;
        /// <summary>The <c>peer_not_allowed_to_send</c> constant, with the value <c>2</c>.</summary>
        public const short peer_not_allowed_to_send = 2;

        public static string GetName(short heartbeatMode)
        {
            switch (heartbeatMode)
            {
            case peer_allowed_to_send:
                return "peer_allowed_to_send";
            case peer_not_allowed_to_send:
                return "peer_not_allowed_to_send";
            default:
                return "UNKNOWN";
            }
        }

        public static string GetText(short heartbeatMode)
        {
            return GetName(heartbeatMode) + "(" + heartbeatMode + ")";
        }

        public static bool IsValid(short heartbeatMode)
        {
            return heartbeatMode >= peer_allowed_to_send && heartbeatMode <= peer_not_allowed_to_send;
        }
    }
}
