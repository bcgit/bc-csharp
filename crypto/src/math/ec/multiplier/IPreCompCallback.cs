using System;

namespace Org.BouncyCastle.Math.EC.Multiplier
{
    /// <summary>Interface for a callback that performs precomputation.</summary>
    public interface IPreCompCallback
    {
        /// <summary>Perform the precomputation.</summary>
        /// <param name="existing">The existing precomputation data, or null.</param>
        /// <returns>The new or updated precomputation data.</returns>
        PreCompInfo Precompute(PreCompInfo existing);
    }
}
