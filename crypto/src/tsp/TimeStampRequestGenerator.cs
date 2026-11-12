using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators.Utilities;

namespace Org.BouncyCastle.Tsp
{
    /// <summary>Generator for RFC 3161 Time Stamp Request objects.</summary>
    /// <remarks>
    /// Optionally set a requested policy, whether the TSA certificate is wanted and any extensions, then call one of
    /// the <c>Generate</c> overloads with the digest of the data to be time-stamped.
    /// </remarks>
    public class TimeStampRequestGenerator
    {
        private readonly X509ExtensionsGenerator m_extGenerator = new X509ExtensionsGenerator();

        private readonly IDigestAlgorithmFinder m_digestAlgorithmFinder;

        private DerObjectIdentifier m_reqPolicy;
        private DerBoolean m_certReq;

        /// <summary>Create a generator using the default digest algorithm finder.</summary>
        public TimeStampRequestGenerator()
            : this(DefaultDigestAlgorithmFinder.Instance)
        {
        }

        /// <summary>Create a generator using the given digest algorithm finder.</summary>
        /// <param name="digestAlgorithmFinder">Maps a digest OID to its AlgorithmIdentifier.</param>
        /// <exception cref="ArgumentNullException"><paramref name="digestAlgorithmFinder"/> is null.</exception>
        public TimeStampRequestGenerator(IDigestAlgorithmFinder digestAlgorithmFinder)
        {
            m_digestAlgorithmFinder = digestAlgorithmFinder ??
                throw new ArgumentNullException(nameof(digestAlgorithmFinder));
        }

        /// <summary>Set the policy under which the requestor wants the time stamp issued.</summary>
        /// <param name="reqPolicy">The object identifier of the policy, or null for none.</param>
        public void SetReqPolicy(DerObjectIdentifier reqPolicy)
        {
            m_reqPolicy = reqPolicy;
        }

        /// <summary>Set the req policy.</summary>
        /// <param name="reqPolicy">The req policy.</param>
        [Obsolete("Use overload taking DerObjectIdentifier instead")]
        public void SetReqPolicy(string reqPolicy)
        {
            SetReqPolicy(new DerObjectIdentifier(reqPolicy));
        }

        /// <summary>Set whether the TSA's certificate should be included in the response.</summary>
        /// <param name="certReq">The value to request, or null to leave it unspecified.</param>
        public void SetCertReq(DerBoolean certReq)
        {
            m_certReq = certReq;
        }

        /// <summary>Set whether the TSA's certificate should be included in the response.</summary>
        /// <param name="certReq">true to request the certificate.</param>
        public void SetCertReq(bool certReq)
        {
            SetCertReq(DerBoolean.GetInstance(certReq));
        }

        /// <summary>Add a given extension field for the standard extensions tag (tag 3).</summary>
        /// <param name="oid">The object identifier of the extension.</param>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="extValue">The value of the extension.</param>
        public virtual void AddExtension(DerObjectIdentifier oid, bool critical, Asn1Encodable extValue)
        {
            m_extGenerator.AddExtension(oid, critical, extValue);
        }

        /// <summary>Add a given extension field for the standard extensions tag.</summary>
        /// <remarks>
        /// The value parameter becomes the contents of the octet string associated with the extension.
        /// </remarks>
        /// <param name="oid">The object identifier of the extension.</param>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="extValue">The contents of the extension's octet string.</param>
        public virtual void AddExtension(DerObjectIdentifier oid, bool critical, byte[] extValue)
        {
            m_extGenerator.AddExtension(oid, critical, extValue);
        }

        // TODO[api] Mark obsolete once TspAlgorithms are changed to OIDs
        //[Obsolete("Use overload taking DerObjectIdentifier or AlgorithmIdentifier instead")]
        /// <summary>Generate a request for the given digest, without a nonce.</summary>
        /// <param name="digestAlgorithm">The object identifier (as a string) of the digest algorithm.</param>
        /// <param name="digest">The digest of the data to be time-stamped.</param>
        /// <returns>The <see cref="TimeStampRequest"/>.</returns>
        public TimeStampRequest Generate(string digestAlgorithm, byte[] digest) =>
            Generate(digestAlgorithm, digest, null);

        // TODO[api] Mark obsolete once TspAlgorithms are changed to OIDs
        //[Obsolete("Use overload taking DerObjectIdentifier or AlgorithmIdentifier instead")]
        /// <summary>Generate a request for the given digest.</summary>
        /// <param name="digestAlgorithmOid">The object identifier (as a string) of the digest algorithm.</param>
        /// <param name="digest">The digest of the data to be time-stamped.</param>
        /// <param name="nonce">A nonce for the request, or null for none.</param>
        /// <returns>The <see cref="TimeStampRequest"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="digestAlgorithmOid"/> is null.</exception>
        public TimeStampRequest Generate(string digestAlgorithmOid, byte[] digest, BigInteger nonce)
        {
            if (digestAlgorithmOid == null)
                throw new ArgumentNullException(nameof(digestAlgorithmOid));

            return Generate(new DerObjectIdentifier(digestAlgorithmOid), digest, nonce);
        }

        /// <summary>Generate a request for the given digest, without a nonce.</summary>
        /// <param name="digestAlgorithm">The object identifier of the digest algorithm.</param>
        /// <param name="digest">The digest of the data to be time-stamped.</param>
        /// <returns>The <see cref="TimeStampRequest"/>.</returns>
        public virtual TimeStampRequest Generate(DerObjectIdentifier digestAlgorithm, byte[] digest) =>
            Generate(digestAlgorithm, digest, null);

        /// <summary>Generate a request for the given digest.</summary>
        /// <param name="digestAlgorithm">The object identifier of the digest algorithm.</param>
        /// <param name="digest">The digest of the data to be time-stamped.</param>
        /// <param name="nonce">A nonce for the request, or null for none.</param>
        /// <returns>The <see cref="TimeStampRequest"/>.</returns>
        public virtual TimeStampRequest Generate(DerObjectIdentifier digestAlgorithm, byte[] digest, BigInteger nonce) =>
            Generate(m_digestAlgorithmFinder.Find(digestAlgorithm), digest, nonce);

        /// <summary>Generate a request for the given digest, without a nonce.</summary>
        /// <param name="digestAlgorithm">The digest algorithm identifier.</param>
        /// <param name="digest">The digest of the data to be time-stamped.</param>
        /// <returns>The <see cref="TimeStampRequest"/>.</returns>
        public virtual TimeStampRequest Generate(AlgorithmIdentifier digestAlgorithm, byte[] digest) =>
            Generate(digestAlgorithm, digest, null);

        /// <summary>Generate a request for the given digest.</summary>
        /// <param name="digestAlgorithm">The digest algorithm identifier.</param>
        /// <param name="digest">The digest of the data to be time-stamped.</param>
        /// <param name="nonce">A nonce for the request, or null for none.</param>
        /// <returns>The <see cref="TimeStampRequest"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="digestAlgorithm"/> is null.</exception>
        public virtual TimeStampRequest Generate(AlgorithmIdentifier digestAlgorithm, byte[] digest, BigInteger nonce)
        {
            if (digestAlgorithm == null)
                throw new ArgumentNullException(nameof(digestAlgorithm));

            MessageImprint messageImprint = new MessageImprint(digestAlgorithm, digest);
            DerInteger reqNonce = nonce == null ? null : new DerInteger(nonce);
            X509Extensions ext = m_extGenerator.IsEmpty ? null : m_extGenerator.Generate();

            return new TimeStampRequest(new TimeStampReq(messageImprint, m_reqPolicy, reqNonce, m_certReq, ext));
        }
    }
}
