using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Operators.Utilities;

namespace Org.BouncyCastle.Tsp
{
    /**
	 * Generator for RFC 3161 Time Stamp Request objects.
	 */
    public class TimeStampRequestGenerator
	{
        private readonly X509ExtensionsGenerator m_extGenerator = new X509ExtensionsGenerator();

        private readonly IDigestAlgorithmFinder m_digestAlgorithmFinder;

		private DerObjectIdentifier m_reqPolicy;
		private DerBoolean m_certReq;

		public TimeStampRequestGenerator()
			: this(DefaultDigestAlgorithmFinder.Instance)
		{
		}

        public TimeStampRequestGenerator(IDigestAlgorithmFinder digestAlgorithmFinder)
		{
			m_digestAlgorithmFinder = digestAlgorithmFinder ??
				throw new ArgumentNullException(nameof(digestAlgorithmFinder));
		}

        public void SetReqPolicy(DerObjectIdentifier reqPolicy)
        {
            m_reqPolicy = reqPolicy;
        }

		[Obsolete("Use overload taking DerObjectIdentifier instead")]
        public void SetReqPolicy(string reqPolicy)
		{
			SetReqPolicy(new DerObjectIdentifier(reqPolicy));
		}

        public void SetCertReq(DerBoolean certReq)
        {
            m_certReq = certReq;
        }

        public void SetCertReq(bool certReq)
		{
			SetCertReq(DerBoolean.GetInstance(certReq));
		}

        /**
		 * add a given extension field for the standard extensions tag (tag 3)
		 * @throws IOException
		 */
        public virtual void AddExtension(DerObjectIdentifier oid, bool critical, Asn1Encodable extValue)
		{
            m_extGenerator.AddExtension(oid, critical, extValue);
        }

        /**
		 * add a given extension field for the standard extensions tag
		 * The value parameter becomes the contents of the octet string associated
		 * with the extension.
		 */
        public virtual void AddExtension(DerObjectIdentifier oid, bool critical, byte[] extValue)
		{
            m_extGenerator.AddExtension(oid, critical, extValue);
		}

        // TODO[api] Mark obsolete once TspAlgorithms are changed to OIDs
        //[Obsolete("Use overload taking DerObjectIdentifier or AlgorithmIdentifier instead")]
        public TimeStampRequest Generate(string digestAlgorithm, byte[] digest) =>
			Generate(digestAlgorithm, digest, null);

        // TODO[api] Mark obsolete once TspAlgorithms are changed to OIDs
        //[Obsolete("Use overload taking DerObjectIdentifier or AlgorithmIdentifier instead")]
        public TimeStampRequest Generate(string digestAlgorithmOid, byte[] digest, BigInteger nonce)
		{
			if (digestAlgorithmOid == null)
				throw new ArgumentNullException(nameof(digestAlgorithmOid));

            return Generate(new DerObjectIdentifier(digestAlgorithmOid), digest, nonce);
		}

        public virtual TimeStampRequest Generate(DerObjectIdentifier digestAlgorithm, byte[] digest) =>
            Generate(digestAlgorithm, digest, null);

        public virtual TimeStampRequest Generate(DerObjectIdentifier digestAlgorithm, byte[] digest, BigInteger nonce) =>
            Generate(m_digestAlgorithmFinder.Find(digestAlgorithm), digest, nonce);

        public virtual TimeStampRequest Generate(AlgorithmIdentifier digestAlgorithm, byte[] digest) =>
            Generate(digestAlgorithm, digest, null);

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
