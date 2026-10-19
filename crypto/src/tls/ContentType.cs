using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 2246 6.2.1</summary>
    public abstract class ContentType
    {
        /// <summary>The <c>change_cipher_spec</c> constant, with the value <c>20</c>.</summary>
        public const short change_cipher_spec = 20;
        /// <summary>The <c>alert</c> constant, with the value <c>21</c>.</summary>
        public const short alert = 21;
        /// <summary>The <c>handshake</c> constant, with the value <c>22</c>.</summary>
        public const short handshake = 22;
        /// <summary>The <c>application_data</c> constant, with the value <c>23</c>.</summary>
        public const short application_data = 23;
        /// <summary>The <c>heartbeat</c> constant, with the value <c>24</c>.</summary>
        public const short heartbeat = 24;
        /// <summary>The <c>tls12_cid</c> constant, with the value <c>25</c>.</summary>
        public const short tls12_cid = 25;

        /// <summary>Get the name of the given content type.</summary>
        /// <param name="contentType">The content type.</param>
        /// <returns>The name.</returns>
        public static string GetName(short contentType)
        {
            switch (contentType)
            {
            case alert:
                return "alert";
            case application_data:
                return "application_data";
            case change_cipher_spec:
                return "change_cipher_spec";
            case handshake:
                return "handshake";
            case heartbeat:
                return "heartbeat";
            case tls12_cid:
                return "tls12_cid";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given content type, made up of its name and its numeric value.
        /// </summary>
        /// <param name="contentType">The content type.</param>
        /// <returns>The text.</returns>
        public static string GetText(short contentType)
        {
            return GetName(contentType) + "(" + contentType + ")";
        }
    }
}
