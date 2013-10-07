namespace Org.BouncyCastle.Crypto.Tls
{

    /*
     * RFC 6520 3.
     */
    public class HeartbeatMessageType
    {
        public const short heartbeat_request = 1;
        public const short heartbeat_response = 2;

        public static bool isValid(short heartbeatMessageType)
        {
            return heartbeatMessageType >= heartbeat_request && heartbeatMessageType <= heartbeat_response;
        }
    }


}