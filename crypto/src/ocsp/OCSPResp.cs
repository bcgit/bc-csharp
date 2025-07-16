using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;

namespace Org.BouncyCastle.Ocsp
{
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

        public OcspResp(OcspResponse resp)
        {
            m_ocspResponse = resp;
        }

        public OcspResp(byte[] resp)
            : this(ParseOcspResponse(resp))
        {
        }

        public OcspResp(Stream inStr)
            : this(ParseOcspResponse(inStr))
        {
        }

        public int Status => m_ocspResponse.ResponseStatus.IntValueExact;

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

        /**
         * return the ASN.1 encoded representation of this object.
         */
        public byte[] GetEncoded() => m_ocspResponse.GetEncoded();

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is OcspResp that
                && m_ocspResponse.Equals(that.m_ocspResponse);
        }

        public override int GetHashCode() => m_ocspResponse.GetHashCode();

        public OcspResponse ToAsn1Structure() => m_ocspResponse;
    }
}
