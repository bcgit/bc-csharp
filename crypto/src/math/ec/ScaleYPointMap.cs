using System;

namespace Org.BouncyCastle.Math.EC
{
    public class ScaleYPointMap
        : ECPointMap
    {
        protected readonly ECFieldElement scale;

        /// <summary>Create a new <see cref="ScaleYPointMap"/>.</summary>
        /// <param name="scale">The scale.</param>
        public ScaleYPointMap(ECFieldElement scale)
        {
            this.scale = scale;
        }

        /// <inheritdoc/>
        public virtual ECPoint Map(ECPoint p)
        {
            return p.ScaleY(scale);
        }
    }
}
