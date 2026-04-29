using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;

namespace Org.BouncyCastle.Ocsp
{
    /// <summmary>Base generator for an OCSP response.</summmary>
    /// <remarks>
    /// At the moment this only supports the generation of responses containing BasicOCSP responses.
    /// </remarks>
    public class OCSPRespGenerator
    {
        public const int Successful = 0;        // Response has valid confirmations
        public const int MalformedRequest = 1;  // Illegal confirmation request
        public const int InternalError = 2;     // Internal error in issuer
        public const int TryLater = 3;          // Try again later
        // (4) is not used
        public const int SigRequired = 5;       // Must sign the request
        public const int Unauthorized = 6;      // Request unauthorized

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
