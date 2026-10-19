using System;

namespace Org.BouncyCastle.Math.EC.Multiplier
{
    /**
     * Class holding precomputation data for fixed-point multiplications.
     */
    public class FixedPointPreCompInfo
        : PreCompInfo
    {
        protected ECPoint m_offset = null;

        /**
         * Lookup table for the precomputed <code>ECPoint</code>s used for a fixed point multiplication.
         */
        protected ECLookupTable m_lookupTable = null;

        /**
         * The width used for the precomputation. If a larger width precomputation
         * is already available this may be larger than was requested, so calling
         * code should refer to the actual width.
         */
        protected int m_width = -1;

        /// <summary>Gets or sets the lookup table.</summary>
        public virtual ECLookupTable LookupTable
        {
            get { return m_lookupTable; }
            set { this.m_lookupTable = value; }
        }

        /// <summary>Gets or sets the offset.</summary>
        public virtual ECPoint Offset
        {
            get { return m_offset; }
            set { this.m_offset = value; }
        }

        /// <summary>Gets or sets the width.</summary>
        public virtual int Width
        {
            get { return m_width; }
            set { this.m_width = value; }
        }
    }
}
