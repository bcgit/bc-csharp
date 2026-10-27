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
    /// <summary>Base class for an RFC 3161 Time Stamp Request.</summary>
    public class TimeStampRequest
        : X509ExtensionBase
    {
        private static TimeStampReq ParseTimeStampReq(byte[] encoding)
        {
            try
            {
                var asn1Object = Asn1Object.FromByteArray(encoding)
                    ?? throw new IOException("no ASN.1 object found in request");

                return TimeStampReq.GetInstance(asn1Object);
            }
            catch (IOException)
            {
                throw;
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
                var asn1Object = Asn1Object.FromStream(input)
                    ?? throw new IOException("no ASN.1 object found in request");

                return TimeStampReq.GetInstance(asn1Object);
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception e)
            {
                // TODO[api]
                //throw new TspException("malformed timestamp request: " + e, e);
                throw new IOException("malformed request: " + e);
            }
        }

        private readonly TimeStampReq m_req;

        /// <summary>Create from an existing ASN.1 TimeStampReq structure.</summary>
        /// <param name="req">The ASN.1 structure.</param>
        /// <exception cref="ArgumentNullException"><paramref name="req"/> is null.</exception>
        public TimeStampRequest(TimeStampReq req)
        {
            m_req = req ?? throw new ArgumentNullException(nameof(req));
        }

        /// <summary>Create a TimeStampRequest from the passed-in byte array.</summary>
        /// <param name="req">the byte array containing the encoded request.</param>
        /// <exception cref="IOException">if the request is malformed.</exception>
        // TODO[api] TspException
        public TimeStampRequest(byte[] req)
            : this(ParseTimeStampReq(req))
        {
        }

        /// <summary>Create a TimeStampRequest from the passed-in stream.</summary>
        /// <param name="input">the stream containing the encoded request.</param>
        /// <exception cref="IOException">if the request is malformed.</exception>
        // TODO[api] TspException
        public TimeStampRequest(Stream input)
            : this(ParseTimeStampReq(input))
        {
        }

        /// <summary>Return the underlying ASN.1 structure.</summary>
        public TimeStampReq TimeStampReq => m_req;

        /// <summary>Gets the version of the request.</summary>
        public int Version => m_req.Version.IntValueExact;

        /// <summary>Gets the message imprint (hash algorithm and digest) to be time-stamped.</summary>
        public MessageImprint MessageImprint => m_req.MessageImprint;

        /// <summary>Gets the hash algorithm of the message imprint.</summary>
        public AlgorithmIdentifier MessageImprintAlgID => MessageImprint.HashAlgorithm;

        /// <summary>Gets the message imprint alg oid.</summary>
        [Obsolete("Will be removed")]
        public string MessageImprintAlgOid => MessageImprintAlgID.Algorithm.Id;

        /// <summary>Gets the digest of the message imprint.</summary>
        public Asn1OctetString MessageImprintDigest => MessageImprint.HashedMessage;

        /// <summary>Return the digest of the message imprint.</summary>
        public byte[] GetMessageImprintDigest() => MessageImprint.GetHashedMessage();

        /// <summary>Gets the req policy.</summary>
        [Obsolete("Will be removed")]
        public string ReqPolicy => m_req.ReqPolicy?.Id;

        // TODO[api] Change this to return the DerInteger?
        /// <summary>Gets the nonce included in the request, or null if there is none.</summary>
        public BigInteger Nonce => m_req.Nonce?.Value;

        /// <summary>Gets whether the requestor asked for the TSA's certificate to be in the response.</summary>
        public bool CertReq => (m_req.CertReq ?? DerBoolean.False).IsTrue;

        /// <summary>
        /// Validate the timestamp request, checking the digest to see if it is of an accepted type and whether it is
        /// of the correct length for the algorithm specified.
        /// </summary>
        /// <param name="algorithms">A list of string OIDs giving accepted algorithms.</param>
        /// <param name="policies">If non-null, a list of policies we are willing to sign under.</param>
        /// <param name="extensions">If non-null, a list of extensions we are willing to accept.</param>
        /// <exception cref="TspValidationException">The request is invalid.</exception>
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

        /// <summary>Return the ASN.1 encoded representation of this object.</summary>
        public byte[] GetEncoded() => m_req.GetEncoded();

        internal X509Extensions Extensions => m_req.Extensions;

        /// <summary>Gets whether the request carries any extensions.</summary>
        public virtual bool HasExtensions => Extensions != null;

        /// <summary>Return the object identifiers of the extensions in the request.</summary>
        public virtual IList<DerObjectIdentifier> GetExtensionOids() => TspUtil.GetExtensionOids(Extensions);

        /// <inheritdoc/>
        protected override X509Extensions GetX509Extensions() => Extensions;
    }
}
