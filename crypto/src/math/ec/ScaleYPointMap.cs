using System;

namespace Org.BouncyCastle.Math.EC
{
    /// <summary>A point map that multiplies the y-coordinate by a scale factor.</summary>
    public class ScaleYPointMap
        : ECPointMap
    {
        /// <summary>The scale factor.</summary>
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
