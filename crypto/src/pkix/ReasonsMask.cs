using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>
    /// This class helps to handle CRL revocation reasons mask. Each CRL handles a certain set of revocation reasons.
    /// </summary>
    internal sealed class ReasonsMask
    {
        /// <summary>Value with all revocation reasons flags set.</summary>
        internal static readonly int AllReasons = ReasonFlags.AACompromise | ReasonFlags.AffiliationChanged |
            ReasonFlags.CACompromise | ReasonFlags.CertificateHold | ReasonFlags.CessationOfOperation |
            ReasonFlags.KeyCompromise | ReasonFlags.PrivilegeWithdrawn | ReasonFlags.Unused | ReasonFlags.Superseded;

        private int m_reasons;

        /// <summary>
        /// A reason mask with no reason.
        /// </summary>
        internal ReasonsMask()
            : this(0)
        {
        }

        /// <summary>
        /// Constructs a reason mask with the given reasons.
        /// </summary>
        /// <param name="reasons">The reasons.</param>
        internal ReasonsMask(int reasons)
        {
            m_reasons = reasons;
        }

        /// <summary>Adds all reasons from the reasons mask to this mask.</summary>
        /// <param name="mask">The reasons mask to add.</param>
        internal void AddReasons(ReasonsMask mask)
        {
            m_reasons |= mask.m_reasons;
        }

        /// <summary>
        /// Returns <code>true</code> if this reasons mask contains all possible reasons.
        /// </summary>
        /// <returns><c>true</c> if this reasons mask contains all possible reasons.</returns>
        internal bool IsAllReasons => !HasNewReasons(m_reasons, AllReasons);

        /// <summary>
        /// Returns <c>true</c> if the passed reasons mask has new reasons.
        /// </summary>
        /// <param name="mask">The reasons mask which should be tested for new reasons.</param>
        /// <returns><c>true</c> if the passed reasons mask has one or more new reasons.</returns>
        internal bool HasNewReasons(ReasonsMask mask) => HasNewReasons(m_reasons, mask.m_reasons);

        private static bool HasNewReasons(int existingReasons, int candidateReasons) =>
            (candidateReasons & ~existingReasons) != 0;
    }
}
