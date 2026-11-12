namespace Org.BouncyCastle.Ocsp
{
    /// <summary>The values of the OCSPResponseStatus enumeration (RFC 6960).</summary>
    public abstract class OcspRespStatus
    {
        /// <summary>The response has valid confirmations.</summary>
        public const int Successful = 0;
        /// <summary>The request was not well-formed.</summary>
        public const int MalformedRequest = 1;
        /// <summary>The responder suffered an internal error.</summary>
        public const int InternalError = 2;
        /// <summary>The responder is unable to respond at the moment; try again later.</summary>
        public const int TryLater = 3;
        // NOTE: 4 is not used
        /// <summary>The request must be signed.</summary>
        public const int SigRequired = 5;
        /// <summary>The client is not authorized to make this query to the responder.</summary>
        public const int Unauthorized = 6;
    }
}
