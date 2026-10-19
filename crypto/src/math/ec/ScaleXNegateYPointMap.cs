using System;

namespace Org.BouncyCastle.Math.EC
{
    /// <summary>A point map that multiplies the x-coordinate by a scale factor and negates the y-coordinate.</summary>
    public class ScaleXNegateYPointMap
        : ECPointMap
    {
        /// <summary>The scale factor.</summary>
        protected readonly ECFieldElement scale;

        /// <summary>Create a new <see cref="ScaleXNegateYPointMap"/>.</summary>
        /// <param name="scale">The scale.</param>
        public ScaleXNegateYPointMap(ECFieldElement scale)
        {
            this.scale = scale;
        }

        /// <inheritdoc/>
        public virtual ECPoint Map(ECPoint p)
        {
            return p.ScaleXNegateY(scale);
        }
    }
}
