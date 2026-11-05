using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    /**
     * The XOF of the HQC specification (2026-10-12, Section 3.1): XOF.Init(seed) absorbs the seed into SHAKE256 and
     * XOF.GetBytes squeezes. Earlier specifications appended a fixed domain byte (0x01) to every seed; the current one
     * does not, and the only domain separation left on the XOF is the parameter set's k appended to seedKEM when the
     * KEM key is expanded, see <see cref="HqcEngine.ExpandSecretKey"/>.
     */
    internal sealed class Shake256RandomGenerator
    {
        private readonly ShakeDigest m_digest = new ShakeDigest(256);

        /** XOF.Init(seed). */
        internal Shake256RandomGenerator(byte[] seed, int off, int len)
        {
            Init(seed, off, len);
        }

        /** XOF.Init(seed || domain), the KEM seed expansion's parameter-set binding. */
        internal Shake256RandomGenerator(byte[] seed, int off, int len, byte domain)
        {
            Init(seed, off, len);
            m_digest.Update(domain);
        }

        /** Re-initialise as XOF.Init(seed), discarding any state. */
        internal void Init(byte[] seed, int off, int len)
        {
            Arrays.ValidateSegment(seed, off, len);

            m_digest.Reset();
            m_digest.BlockUpdate(seed, off, len);
        }

        internal void NextBytes(byte[] bytes) => NextBytes(bytes, 0, bytes.Length);

        internal void NextBytes(byte[] bytes, int start, int len) => m_digest.Output(bytes, start, len);

        /**
         * XOF.GetBytes: a plain squeeze of exactly <paramref name="outLen"/> bytes. The earlier reference code squeezed
         * in 8-byte units and discarded the tail of the last unit; the 2026-10-12 reference code squeezes exactly what
         * it uses, so a short read no longer skips bytes of the stream.
         */
        internal void XofGetBytes(byte[] output, int outLen) => m_digest.Output(output, 0, outLen);
    }
}
