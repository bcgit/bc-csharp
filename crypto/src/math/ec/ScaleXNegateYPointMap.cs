using System;

namespace Org.BouncyCastle.Math.EC
{
    public class ScaleXNegateYPointMap
        : ECPointMap
    {
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
