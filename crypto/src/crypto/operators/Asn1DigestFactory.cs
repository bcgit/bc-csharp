using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Operators
{
    /// <summary>A factory for digests identified by an algorithm object identifier.</summary>
    public class Asn1DigestFactory
        : IDigestFactory
    {
        /// <summary>Get the digest factory for an algorithm.</summary>
        /// <param name="oid">The object identifier of the digest algorithm.</param>
        /// <returns>The digest factory.</returns>
        public static Asn1DigestFactory Get(DerObjectIdentifier oid) =>
            new Asn1DigestFactory(DigestUtilities.GetDigest(oid), oid);

        /// <summary>Get the digest factory for an algorithm.</summary>
        /// <param name="mechanism">The name of the digest algorithm.</param>
        /// <returns>The digest factory.</returns>
        public static Asn1DigestFactory Get(string mechanism) => Get(DigestUtilities.GetObjectIdentifier(mechanism));

        private readonly IDigest m_digest;
        private readonly DerObjectIdentifier m_oid;

        /// <summary>Create a new <see cref="Asn1DigestFactory"/>.</summary>
        /// <param name="digest">The digest.</param>
        /// <param name="oid">The object identifier.</param>
        public Asn1DigestFactory(IDigest digest, DerObjectIdentifier oid)
        {
            m_digest = digest;
            m_oid = oid;
        }

        /// <inheritdoc/>
        public virtual object AlgorithmDetails => new AlgorithmIdentifier(m_oid);

        /// <inheritdoc/>
        public virtual int DigestLength => m_digest.GetDigestSize();

        /// <inheritdoc/>
        public virtual IStreamCalculator<IBlockResult> CreateCalculator() => new DefaultDigestCalculator(m_digest);
    }
}
