using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tsp
{
    /**
	 * Base class for an RFC 3161 Time Stamp Request.
	 */
    public class TimeStampRequest
        : X509ExtensionBase
    {
        private static TimeStampReq ParseTimeStampReq(byte[] encoding)
        {
            try
            {
                return TimeStampReq.GetInstance(encoding);
            }
            catch (Exception e)
            {
                // TODO[api]
                //throw new TspException("malformed timestamp request: " + e, e);
                throw new IOException("malformed request: " + e);
            }
        }

        private static TimeStampReq ParseTimeStampReq(Stream input)
        {
            try
            {
                return TimeStampReq.GetInstance(Asn1Object.FromStream(input));
            }
            catch (Exception e)
            {
                // TODO[api]
                //throw new TspException("malformed timestamp request: " + e, e);
                throw new IOException("malformed request: " + e);
            }
        }

        private readonly TimeStampReq m_req;

        public TimeStampRequest(TimeStampReq req)
        {
            m_req = req;
        }

        /**
         * Create a TimeStampRequest from the passed-in byte array.
         *
         * @param req byte array containing the request.
         * @throws IOException if the request is malformed.
         */
        public TimeStampRequest(byte[] req)
            : this(ParseTimeStampReq(req))
        {
        }

        /**
         * Create a TimeStampRequest from the passed-in input stream.
         *
         * @param in input stream containing the request.
         * @throws IOException if the request is malformed.
         */
        public TimeStampRequest(Stream input)
            : this(ParseTimeStampReq(input))
        {
        }

        public TimeStampReq TimeStampReq => m_req;

        public int Version => m_req.Version.IntValueExact;

        public MessageImprint MessageImprint => m_req.MessageImprint;

        public AlgorithmIdentifier MessageImprintAlgID => m_req.MessageImprint.HashAlgorithm;

        // TODO[api] Change this to return just the OID itself
        public string MessageImprintAlgOid => m_req.MessageImprint.HashAlgorithm.Algorithm.Id;

        public Asn1OctetString MessageImprintDigest => m_req.MessageImprint.HashedMessage;

        public byte[] GetMessageImprintDigest() => m_req.MessageImprint.GetHashedMessage();

        // TODO[api] Change this to return just the OID itself
        public string ReqPolicy => m_req.ReqPolicy?.Id;

        // TODO[api] Change this to return the DerInteger?
        public BigInteger Nonce => m_req.Nonce?.Value;

        public bool CertReq => (m_req.CertReq ?? DerBoolean.False).IsTrue;

        /**
         * Validate the timestamp request, checking the digest to see if it is of an
         * accepted type and whether it is of the correct length for the algorithm specified.
         *
         * @param algorithms a set of string OIDS giving accepted algorithms.
         * @param policies if non-null a set of policies we are willing to sign under.
         * @param extensions if non-null a set of extensions we are willing to accept.
         * @throws TspException if the request is invalid, or processing fails.
         */
        // TODO[api] These should all hold DerObjectIdentifier
        public void Validate(IList<string> algorithms, IList<string> policies, IList<string> extensions)
        {
            if (algorithms == null)
                throw new TspValidationException("no algorithms associated with request", PkiFailureInfo.BadAlg);

            var messageImprint = MessageImprint;
            var messageImprintAlgID = messageImprint.HashAlgorithm;
            var messageImprintAlgOid = messageImprintAlgID.Algorithm;

            if (!algorithms.Contains(messageImprintAlgOid.GetID()))
                throw new TspValidationException("request contains unknown algorithm", PkiFailureInfo.BadAlg);

            if (policies != null)
            {
                var reqPolicy = m_req.ReqPolicy;
                if (reqPolicy != null && !policies.Contains(reqPolicy.GetID()))
                    throw new TspValidationException("request contains unknown policy", PkiFailureInfo.UnacceptedPolicy);
            }

            if (extensions != null && Extensions != null)
            {
                foreach (var oid in Extensions.ExtensionOids)
                {
                    if (!extensions.Contains(oid.GetID()))
                        throw new TspValidationException("request contains unknown extension", PkiFailureInfo.UnacceptedExtension);
                }
            }

            int digestLength = TspUtil.GetDigestLength(messageImprintAlgOid);

            if (digestLength != messageImprint.HashedMessage.GetOctetsLength())
                throw new TspValidationException("imprint digest the wrong length", PkiFailureInfo.BadDataFormat);
        }

        /**
		 * return the ASN.1 encoded representation of this object.
		 */
        public byte[] GetEncoded() => m_req.GetEncoded();

        internal X509Extensions Extensions => m_req.Extensions;

        public virtual bool HasExtensions => Extensions != null;

        public virtual IList<DerObjectIdentifier> GetExtensionOids() => TspUtil.GetExtensionOids(Extensions);

        protected override X509Extensions GetX509Extensions() => Extensions;
    }
}
