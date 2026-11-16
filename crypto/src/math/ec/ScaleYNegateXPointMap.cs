using System;

namespace Org.BouncyCastle.Math.EC
{
    /// <summary>A point map that multiplies the y-coordinate by a scale factor and negates the x-coordinate.</summary>
    public class ScaleYNegateXPointMap
        : ECPointMap
    {
        /// <summary>The scale factor.</summary>
        protected readonly ECFieldElement scale;

        /// <summary>Create a new <see cref="ScaleYNegateXPointMap"/>.</summary>
        /// <param name="scale">The scale.</param>
        public ScaleYNegateXPointMap(ECFieldElement scale)
        {
            this.scale = scale;
        }

        /// <inheritdoc/>
        public virtual ECPoint Map(ECPoint p)
        {
            return p.ScaleYNegateX(scale);
        }
    }
}
