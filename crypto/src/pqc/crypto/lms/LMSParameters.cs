using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsParameters
    {
        private readonly LMSigParameters m_lmSigParameters;
        private readonly LMOtsParameters m_lmOtsParameters;

        public LmsParameters(LMSigParameters lmSigParameters, LMOtsParameters lmOtsParameters)
        {
            m_lmSigParameters = lmSigParameters;
            m_lmOtsParameters = lmOtsParameters;
        }

        public LMSigParameters LMSigParameters => m_lmSigParameters;

        public LMOtsParameters LMOtsParameters => m_lmOtsParameters;

        /// <summary>A pairing of the two parameter sets, so equal by value.</summary>
        /// <remarks>
        /// Unlike the two halves, which are interned typecodes, this is composed freely by callers: RFC 8554
        /// carries the LMS and LM-OTS typecodes as separate fields, so any pairing can be built. Reference
        /// equality would therefore be wrong here even though it is right for each half.
        /// </remarks>
        public override bool Equals(object obj) =>
            obj is LmsParameters that
            && Objects.Equals(this.m_lmSigParameters, that.m_lmSigParameters)
            && Objects.Equals(this.m_lmOtsParameters, that.m_lmOtsParameters);

        public override int GetHashCode() =>
            31 * Objects.GetHashCode(m_lmSigParameters) + Objects.GetHashCode(m_lmOtsParameters);

        /// <summary>
        /// SP 800-208 sec. 4 requires one hash function throughout a key: the LMS tree and its LM-OTS keys here,
        /// and every level of an HSS hierarchy. A hash function is its digest and its output length, so SHA-256/192
        /// is distinct from SHA-256; that is also what keeps an n=24 parent from deriving a 24-byte seed for an
        /// m=32 child. Applied at key generation only: an existing key is taken as it was made.
        /// </summary>
        internal void CheckHashFunction()
        {
            if (m_lmSigParameters == null || m_lmOtsParameters == null)
                throw new ArgumentException("LMS parameters need both an LMS and an LM-OTS parameter set");

            if (m_lmSigParameters.M != m_lmOtsParameters.N ||
                !m_lmSigParameters.DigestOid.Equals(m_lmOtsParameters.DigestOid))
            {
                throw new ArgumentException(
                    "LMS tree and LM-OTS parameter sets must use the same hash function (SP 800-208 sec. 4)");
            }
        }

        internal bool SameHashFunctionAs(LmsParameters other) =>
            m_lmSigParameters.M == other.m_lmSigParameters.M &&
            m_lmSigParameters.DigestOid.Equals(other.m_lmSigParameters.DigestOid);
    }
}
