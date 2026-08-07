using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tsp
{
    /// <summary>Base class for an RFC 3161 Time Stamp Response.</summary>
    public class TimeStampResponse
    {
        private static TimeStampResp ParseTimeStampResp(byte[] encoding)
        {
            try
            {
                var asn1Object = Asn1Object.FromByteArray(encoding)
                    ?? throw new IOException("no ASN.1 object found in response");

                return TimeStampResp.GetInstance(asn1Object);
            }
            catch (IOException)
            {
                throw;
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
                var asn1Object = Asn1Object.FromStream(input)
                    ?? throw new IOException("no ASN.1 object found in response");

                return TimeStampResp.GetInstance(asn1Object);
            }
            catch (IOException)
            {
                throw;
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
            m_resp = resp ?? throw new ArgumentNullException(nameof(resp));

            if (resp.TimeStampToken != null)
            {
                m_timeStampToken = new TimeStampToken(resp.TimeStampToken);
            }
        }

        /// <summary>Create a TimeStampResponse from the passed-in byte array.</summary>
        /// <param name="resp">the byte array containing the encoded response.</param>
        /// <exception cref="TspException">if the response is malformed.</exception>
        /// <exception cref="IOException">if the byte array doesn't represent an ASN.1 encoding.</exception>
        public TimeStampResponse(byte[] resp)
            : this(ParseTimeStampResp(resp))
        {
        }

        /// <summary>Create a TimeStampResponse from the passed-in stream.</summary>
        /// <param name="input">the stream containing the encoded response.</param>
        /// <exception cref="TspException">if the response is malformed.</exception>
        /// <exception cref="IOException">if the stream doesn't represent an ASN.1 encoding.</exception>
        public TimeStampResponse(Stream input)
            : this(ParseTimeStampResp(input))
        {
        }

        public PkiStatusInfo StatusInfo => m_resp.Status;

        public int Status => StatusInfo.StatusObject.IntValueExact;

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

        public TimeStampResp TimeStampResp => m_resp;

        public TimeStampToken TimeStampToken => m_timeStampToken;

        /// <summary>
        /// Check that this response is a well formed response for the passed in request.
        /// </summary>
        /// <remarks>
        /// Validation includes checking the time stamp token when the response status is 'Granted' or
        /// 'GrantedWithMods'.
        /// </remarks>
        /// <param name="request">The request to be checked against.</param>
        /// <exception cref="TspValidationException">If the request cannot match this response.</exception>
        public void Validate(TimeStampRequest request)
        {
            TimeStampToken tsToken = TimeStampToken;

            if (tsToken != null)
            {
                TimeStampTokenInfo tstInfo = tsToken.TimeStampInfo;

                if (request.Nonce != null && !request.Nonce.Equals(tstInfo.Nonce))
                    throw new TspValidationException("response contains wrong nonce value.");

                if (this.Status != (int)PkiStatus.Granted && this.Status != (int)PkiStatus.GrantedWithMods)
                    throw new TspValidationException("time stamp token found in failed request.");

                if (!X509Utilities.AreEquivalentAlgorithms(tstInfo.HashAlgorithm, request.MessageImprintAlgID))
                    throw new TspValidationException("response for different message imprint algorithm.");

                if (!Arrays.FixedTimeEquals(request.MessageImprintDigest.GetOctets(), tstInfo.MessageImprintDigest.GetOctets()))
                    throw new TspValidationException("response for different message imprint digest.");

                Asn1.Cms.Attribute scV1 = tsToken.SignedAttributes[PkcsObjectIdentifiers.IdAASigningCertificate];
                Asn1.Cms.Attribute scV2 = tsToken.SignedAttributes[PkcsObjectIdentifiers.IdAASigningCertificateV2];

                if (scV1 == null && scV2 == null)
                    throw new TspValidationException("no signing certificate attribute present.");

                if (scV1 != null && scV2 != null)
                {
                    // RFC 5035 5.4. If both attributes exist in a single message, they are independently evaluated.
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

        /// <summary>Return the ASN.1 encoded representation of this object.</summary>
        public byte[] GetEncoded() => m_resp.GetEncoded();

        /// <summary>Return the ASN.1 encoded representation of this object for the specific encoding type.</summary>
        /// <param name="encoding">Encoding style ("DER", "DL", "BER").</param>
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
