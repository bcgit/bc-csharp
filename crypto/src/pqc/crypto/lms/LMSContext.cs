using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Don't implement IDigest on promotion. The context absorbs a fixed prefix at construction and
    // must be finalized exactly once, by OutputQ; only the update methods are meaningful, and the rest of
    // IDigest exists here solely to let callers stream a message in.
    public sealed class LmsContext
        : IDigest
    {
        private readonly byte[] m_c;
        private readonly LMOtsPrivateKey m_privateKey;
        private readonly LMSigParameters m_sigParams;
        private readonly byte[][] m_path;

        private readonly LMOtsPublicKey m_publicKey;
        private readonly object m_signature;
        private LmsSignedPubKey[] m_signedPubKeys;
        private volatile IDigest m_digest;

        // TODO[api] Make internal
        public LmsContext(LMOtsPrivateKey privateKey, LMSigParameters sigParams, IDigest digest, byte[] C,
            byte[][] path)
        {
            m_privateKey = privateKey;
            m_sigParams = sigParams;
            m_digest = digest;
            m_c = C;
            m_path = path;
            m_publicKey = null;
            m_signature = null;
        }

        // TODO[api] Make internal
        public LmsContext(LMOtsPublicKey publicKey, object signature, IDigest digest)
        {
            m_publicKey = publicKey;
            m_signature = signature;
            m_digest = digest;
            m_c = null;
            m_privateKey = null;
            m_sigParams = null;
            m_path = null;
        }

        public byte[] C => m_c;

        // TODO[api] Remove
        [Obsolete("Use 'OutputQ' instead")]
        public byte[] GetQ()
        {
            // Length is the maximum N over the LM-OTS parameter sets, plus the two checksum bytes that the
            // caller appends; OutputQ writes only the N bytes of Q and lets the caller size the buffer.
            const int MAX_HASH = 32;
            byte[] Q = new byte[MAX_HASH + 2];
            OutputQ(Q, 0);
            return Q;
        }

        /// <summary>Write Q, the message hash, to the given buffer. The context cannot be used afterwards.
        /// </summary>
        /// <remarks>A caller that goes on to append the LM-OTS checksum needs two bytes beyond the value
        /// written here.</remarks>
        /// <param name="output">The byte array Q is to be copied into.</param>
        /// <param name="outOff">The offset into the byte array Q is to start at.</param>
        /// <returns>The number of bytes written.</returns>
        public int OutputQ(byte[] output, int outOff)
        {
            IDigest digest = Digest;
            int qLen = digest.GetDigestSize();
            Check.OutputLength(output, outOff, qLen, "output buffer too short");

            digest.DoFinal(output, outOff);
            m_digest = null;
            return qLen;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Write Q, the message hash, to the given span. The context cannot be used afterwards.
        /// </summary>
        /// <remarks>A caller that goes on to append the LM-OTS checksum needs two bytes beyond the value
        /// written here.</remarks>
        /// <param name="output">The span Q is to be copied into.</param>
        /// <returns>The number of bytes written.</returns>
        public int OutputQ(Span<byte> output)
        {
            IDigest digest = Digest;
            int qLen = digest.GetDigestSize();
            Check.OutputLength(output, qLen, "output buffer too short");

            digest.DoFinal(output);
            m_digest = null;
            return qLen;
        }
#endif

        // The digest is finalized by OutputQ and released, so every later use is a caller error.
        private IDigest Digest => m_digest ?? throw new InvalidOperationException("context already used");

        internal byte[][] Path => m_path;

        internal LMOtsPrivateKey PrivateKey => m_privateKey;

        // TODO[api] Make internal
        public LMOtsPublicKey PublicKey => m_publicKey;

        internal LMSigParameters SigParams => m_sigParams;

        public object Signature => m_signature;

        internal LmsSignedPubKey[] SignedPubKeys => m_signedPubKeys;

        internal LmsContext WithSignedPublicKeys(LmsSignedPubKey[] signedPubKeys)
        {
            m_signedPubKeys = signedPubKeys;
            return this;
        }

        public string AlgorithmName => Digest.AlgorithmName;

        public int GetDigestSize() => Digest.GetDigestSize();

        public int GetByteLength() => Digest.GetByteLength();

        public void Update(byte input)
        {
            Digest.Update(input);
        }

        public void BlockUpdate(byte[] input, int inOff, int len)
        {
            Digest.BlockUpdate(input, inOff, len);
        }

        // Finalizing here would return H(prefix || message), which looks like Q but leaves the digest reset:
        // OutputQ would then hash nothing at all and the signature would be over a constant.
        public int DoFinal(byte[] output, int outOff) => throw NoDirectFinalization();

        // A reset discards the prefix absorbed at construction, which cannot be replaced.
        public void Reset() => throw new NotSupportedException("LmsContext cannot be reset");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            Digest.BlockUpdate(input);
        }

        public int DoFinal(Span<byte> output) => throw NoDirectFinalization();
#endif

        private static NotSupportedException NoDirectFinalization() =>
            new NotSupportedException("LmsContext must be finalized by OutputQ");
    }
}
