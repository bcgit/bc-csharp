using System;

namespace Org.BouncyCastle.Math.EC
{
    /// <summary>A point map that multiplies the x-coordinate by a scale factor.</summary>
    public class ScaleXPointMap
        : ECPointMap
    {
        /// <summary>The scale factor.</summary>
        protected readonly ECFieldElement scale;

        /// <summary>Create a new <see cref="ScaleXPointMap"/>.</summary>
        /// <param name="scale">The scale.</param>
        public ScaleXPointMap(ECFieldElement scale)
        {
            this.scale = scale;
        }

        /// <inheritdoc/>
        public virtual ECPoint Map(ECPoint p)
        {
            return p.ScaleX(scale);
        }
    }
}
