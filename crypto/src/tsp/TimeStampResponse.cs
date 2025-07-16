using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tsp
{
    /**
	 * Base class for an RFC 3161 Time Stamp Response object.
	 */
    public class TimeStampResponse
    {
        private static TimeStampResp ParseTimeStampResp(byte[] encoding)
        {
            try
            {
                return TimeStampResp.GetInstance(encoding);
            }
            catch (Exception e)
            {
                throw new TspException("malformed timestamp response: " + e, e);
            }
        }

        private static TimeStampResp ParseTimeStampResp(Stream input)
        {
            try
            {
                return TimeStampResp.GetInstance(Asn1Object.FromStream(input));
            }
            catch (Exception e)
            {
                throw new TspException("malformed timestamp response: " + e, e);
            }
        }

        private readonly TimeStampResp m_resp;
        private readonly TimeStampToken m_timeStampToken;

        public TimeStampResponse(TimeStampResp resp)
        {
            m_resp = resp;

            if (resp.TimeStampToken != null)
            {
                m_timeStampToken = new TimeStampToken(resp.TimeStampToken);
            }
        }

        /**
         * Create a TimeStampResponse from a byte array containing an ASN.1 encoding.
         *
         * @param resp the byte array containing the encoded response.
         * @throws TspException if the response is malformed.
         * @throws IOException if the byte array doesn't represent an ASN.1 encoding.
         */
        public TimeStampResponse(byte[] resp)
            : this(ParseTimeStampResp(resp))
        {
        }

        /**
         * Create a TimeStampResponse from an input stream containing an ASN.1 encoding.
         *
         * @param input the input stream containing the encoded response.
         * @throws TspException if the response is malformed.
         * @throws IOException if the stream doesn't represent an ASN.1 encoding.
         */
        public TimeStampResponse(Stream input)
            : this(ParseTimeStampResp(input))
        {
        }

        public int Status => m_resp.Status.StatusObject.IntValueExact;

        public string GetStatusString()
        {
            if (m_resp.Status.StatusString == null)
                return null;

            StringBuilder sb = new StringBuilder();
            PkiFreeText text = m_resp.Status.StatusString;
            for (int i = 0; i < text.Count; ++i)
            {
                sb.Append(text[i].GetString());
            }
            return sb.ToString();
        }

        public PkiFailureInfo GetFailInfo()
        {
            if (m_resp.Status.FailInfo == null)
                return null;

            return new PkiFailureInfo(m_resp.Status.FailInfo);
        }

        public TimeStampToken TimeStampToken => m_timeStampToken;

        /**
         * Check this response against to see if it a well formed response for
         * the passed in request. Validation will include checking the time stamp
         * token if the response status is GRANTED or GRANTED_WITH_MODS.
         *
         * @param request the request to be checked against
         * @throws TspException if the request can not match this response.
         */
        public void Validate(TimeStampRequest request)
        {
            TimeStampToken tok = this.TimeStampToken;

            if (tok != null)
            {
                TimeStampTokenInfo tstInfo = tok.TimeStampInfo;

                if (request.Nonce != null && !request.Nonce.Equals(tstInfo.Nonce))
                    throw new TspValidationException("response contains wrong nonce value.");

                if (this.Status != (int)PkiStatus.Granted && this.Status != (int)PkiStatus.GrantedWithMods)
                    throw new TspValidationException("time stamp token found in failed request.");

                // TODO Should be (absent-parameters-flexible) equality of the whole AlgorithmIdentifier?
                if (!tstInfo.MessageImprintAlgOid.Equals(request.MessageImprintAlgOid))
                    throw new TspValidationException("response for different message imprint algorithm.");

                if (!Arrays.FixedTimeEquals(request.MessageImprintDigest.GetOctets(), tstInfo.MessageImprintDigest.GetOctets()))
                    throw new TspValidationException("response for different message imprint digest.");

                Asn1.Cms.Attribute scV1 = tok.SignedAttributes[PkcsObjectIdentifiers.IdAASigningCertificate];
                Asn1.Cms.Attribute scV2 = tok.SignedAttributes[PkcsObjectIdentifiers.IdAASigningCertificateV2];

                if (scV1 == null && scV2 == null)
                    throw new TspValidationException("no signing certificate attribute present.");

                if (scV1 != null && scV2 != null)
                {
                    /*
					 * RFC 5035 5.4. If both attributes exist in a single message,
					 * they are independently evaluated. 
					 */
                }

                var reqPolicy = request.TimeStampReq.ReqPolicy;
                if (reqPolicy != null && !reqPolicy.Equals(tstInfo.TstInfo.Policy))
                    throw new TspValidationException("TSA policy wrong for request.");
            }
            else if (this.Status == (int)PkiStatus.Granted || this.Status == (int)PkiStatus.GrantedWithMods)
            {
                throw new TspValidationException("no time stamp token found and one expected.");
            }
        }

        /**
		 * return the ASN.1 encoded representation of this object.
		 */
        public byte[] GetEncoded() => m_resp.GetEncoded();

        /**
         * return the ASN.1 encoded representation of this object for the specific encoding type.
         *
         * @param encoding encoding style ("DER", "DL", "BER")
         */
        public byte[] GetEncoded(string encoding)
        {
            Asn1Encodable asn1Encodable = m_resp;
            if (Asn1Encodable.DL.Equals(encoding))
            {
                asn1Encodable = m_timeStampToken == null
                    ? new DLSequence(m_resp.Status)
                    : new DLSequence(m_resp.Status, m_timeStampToken.ToCmsSignedData().ContentInfo);
            }
            return asn1Encodable.GetEncoded(encoding);
        }
    }
}
