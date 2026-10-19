using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;

namespace Org.BouncyCastle.Ocsp
{
    /// <summary>An OCSP response (RFC 6960): a status, plus response bytes when the status is successful.</summary>
    /// <remarks>
    /// Instances can be parsed from an encoding or produced by <see cref="OCSPRespGenerator"/>. Use
    /// <see cref="Status"/> to check the outcome and <see cref="GetResponseObject"/> to obtain the
    /// <see cref="BasicOcspResp"/> carrying the certificate statuses.
    /// </remarks>
    public class OcspResp
    {
        private static OcspResponse ParseOcspResponse(byte[] encoding)
        {
            try
            {
                return OcspResponse.GetInstance(encoding);
            }
            catch (Exception e)
            {
                throw new IOException("malformed response: " + e.Message, e);
            }
        }

        private static OcspResponse ParseOcspResponse(Stream input)
        {
            try
            {
                return OcspResponse.GetInstance(Asn1Object.FromStream(input));
            }
            catch (Exception e)
            {
                throw new IOException("malformed response: " + e.Message, e);
            }
        }

        private readonly OcspResponse m_ocspResponse;

        /// <summary>Create from an existing ASN.1 OcspResponse structure.</summary>
        /// <param name="resp">The ASN.1 structure.</param>
        public OcspResp(OcspResponse resp)
        {
            m_ocspResponse = resp;
        }

        /// <summary>Parse a response from its encoding.</summary>
        /// <param name="resp">The encoded OCSP response.</param>
        /// <exception cref="IOException">The encoding is malformed.</exception>
        public OcspResp(byte[] resp)
            : this(ParseOcspResponse(resp))
        {
        }

        /// <summary>Parse a response from a stream containing its encoding.</summary>
        /// <param name="inStr">A stream positioned at the encoded OCSP response.</param>
        /// <exception cref="IOException">The encoding is malformed.</exception>
        public OcspResp(Stream inStr)
            : this(ParseOcspResponse(inStr))
        {
        }

        /// <summary>Gets the response status; see <see cref="OcspRespStatus"/> for the possible values.</summary>
        public int Status => m_ocspResponse.ResponseStatus.IntValueExact;

        /// <summary>Return the response carried by this object.</summary>
        /// <returns>
        /// A <see cref="BasicOcspResp"/> for basic responses, the raw response octets for other response types, or
        /// null if the response has no response bytes (typically because <see cref="Status"/> is not successful).
        /// </returns>
        /// <exception cref="OcspException">A basic response could not be decoded.</exception>
        public object GetResponseObject()
        {
            ResponseBytes rb = m_ocspResponse.ResponseBytes;

            if (rb == null)
                return null;

            if (OcspObjectIdentifiers.PkixOcspBasic.Equals(rb.ResponseType))
            {
                try
                {
                    return new BasicOcspResp(BasicOcspResponse.GetInstance(rb.Response.GetOctets()));
                }
                catch (Exception e)
                {
                    throw new OcspException("problem decoding object: " + e, e);
                }
            }

            return rb.Response;
        }

        /// <summary>Return the ASN.1 encoded representation of this object.</summary>
        public byte[] GetEncoded() => m_ocspResponse.GetEncoded();

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is OcspResp that
                && m_ocspResponse.Equals(that.m_ocspResponse);
        }

        public override int GetHashCode() => m_ocspResponse.GetHashCode();

        /// <summary>Return the underlying ASN.1 structure.</summary>
        public OcspResponse ToAsn1Structure() => m_ocspResponse;
    }
}
