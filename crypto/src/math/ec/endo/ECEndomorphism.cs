using System;

namespace Org.BouncyCastle.Math.EC.Endo
{
    public interface ECEndomorphism
    {
        /// <summary>Gets the point map.</summary>
        ECPointMap PointMap { get; }

        /// <summary>Gets a value indicating whether this has efficient point map.</summary>
        bool HasEfficientPointMap { get; }
    }
}
