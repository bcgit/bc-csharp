using System;

namespace Org.BouncyCastle.Math.EC
{
    public class ScaleYNegateXPointMap
        : ECPointMap
    {
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
