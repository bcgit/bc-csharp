using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;

namespace Org.BouncyCastle.Ocsp
{
    /// <summary>Base generator for an OCSP response.</summary>
    /// <remarks>
    /// At the moment this only supports the generation of responses containing BasicOCSP responses.
    /// </remarks>
    public class OCSPRespGenerator
    {
        /// <summary>The response has valid confirmations.</summary>
        public const int Successful = 0;
        /// <summary>The request was not well-formed.</summary>
        public const int MalformedRequest = 1;
        /// <summary>The responder suffered an internal error.</summary>
        public const int InternalError = 2;
        /// <summary>The responder is unable to respond at the moment; try again later.</summary>
        public const int TryLater = 3;
        // (4) is not used
        /// <summary>The request must be signed.</summary>
        public const int SigRequired = 5;
        /// <summary>The client is not authorized to make this query to the responder.</summary>
        public const int Unauthorized = 6;

        /// <summary>Generate an OCSP response.</summary>
        /// <param name="status">The response status; see <see cref="OcspRespStatus"/> for the possible values.</param>
        /// <param name="response">
        /// The <see cref="BasicOcspResp"/> to include, or null if there is none (as for any unsuccessful status).
        /// </param>
        /// <returns>The <see cref="OcspResp"/>.</returns>
        /// <exception cref="OcspException">
        /// <paramref name="response"/> is of an unsupported type, or could not be encoded.
        /// </exception>
        public OcspResp Generate(int status, object response)
        {
            if (response == null)
                return new OcspResp(new OcspResponse(new OcspResponseStatus(status), null));

            if (response is BasicOcspResp basicOcspResp)
            {
                Asn1OctetString octs;
                try
                {
                    octs = new DerOctetString(basicOcspResp.GetEncoded());
                }
                catch (Exception e)
                {
                    throw new OcspException("can't encode object.", e);
                }

                var responseBytes = new ResponseBytes(OcspObjectIdentifiers.PkixOcspBasic, octs);

                return new OcspResp(new OcspResponse(new OcspResponseStatus(status), responseBytes));
            }

            throw new OcspException("unknown response object");
        }
    }
}
