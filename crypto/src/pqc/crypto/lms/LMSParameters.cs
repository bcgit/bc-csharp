using System;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsParameters
    {
        private readonly LMSigParameters m_sigParameters;
        private readonly LMOtsParameters m_otsParameters;

        // TODO[api] Rename parameters like fields
        public LmsParameters(LMSigParameters lmSigParameters, LMOtsParameters lmOtsParameters)
        {
            m_sigParameters = lmSigParameters ?? throw new ArgumentNullException(nameof(lmSigParameters));
            m_otsParameters = lmOtsParameters ?? throw new ArgumentNullException(nameof(lmOtsParameters));
        }

        // TODO[api] Rename to SigParameters
        public LMSigParameters LMSigParameters => m_sigParameters;

        // TODO[api] Rename to OtsParameters
        public LMOtsParameters LMOtsParameters => m_otsParameters;

        /// <summary>A pairing of the two parameter sets, so equal by value.</summary>
        /// <remarks>
        /// Unlike the two halves, which are interned typecodes, this is composed freely by callers: RFC 8554
        /// carries the LMS and LM-OTS typecodes as separate fields, so any pairing can be built. Reference
        /// equality would therefore be wrong here even though it is right for each half.
        /// </remarks>
        public override bool Equals(object obj) =>
            obj is LmsParameters that
            && m_sigParameters.Equals(that.m_sigParameters)
            && m_otsParameters.Equals(that.m_otsParameters);

        public override int GetHashCode() => 31 * m_sigParameters.GetHashCode() + m_otsParameters.GetHashCode();

        /// <summary>
        /// Whether the LMS tree and its LM-OTS keys use one hash function, as SP 800-208 sec. 4 requires throughout
        /// a key (and, via <see cref="UsesSameLmsHashFunctionAs"/>, across every level of an HSS hierarchy). A hash
        /// function is its digest and its output length, so SHA-256/192 is distinct from SHA-256; that is also what
        /// keeps an n=24 parent from deriving a 24-byte seed for an m=32 child. Checked by the key generation
        /// parameters only: an existing key is taken as it was made.
        /// </summary>
        internal bool UsesOneHashFunction() =>
            m_sigParameters.M == m_otsParameters.N && m_sigParameters.DigestOid.Equals(m_otsParameters.DigestOid);

        internal bool UsesSameLmsHashFunctionAs(LmsParameters other) =>
            m_sigParameters.M == other.m_sigParameters.M &&
            m_sigParameters.DigestOid.Equals(other.m_sigParameters.DigestOid);
    }
}
