using System;

namespace Org.BouncyCastle.Math.EC
{
    public class ScaleXPointMap
        : ECPointMap
    {
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
