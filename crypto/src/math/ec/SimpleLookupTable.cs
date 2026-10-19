using System;

namespace Org.BouncyCastle.Math.EC
{
    public class SimpleLookupTable
        : AbstractECLookupTable
    {
        private static ECPoint[] Copy(ECPoint[] points, int off, int len)
        {
            ECPoint[] result = new ECPoint[len];
            for (int i = 0; i < len; ++i)
            {
                result[i] = points[off + i];
            }
            return result;
        }

        private readonly ECPoint[] points;

        /// <summary>Create a new <see cref="SimpleLookupTable"/>.</summary>
        /// <param name="points">The points.</param>
        /// <param name="off">The offset into the array.</param>
        /// <param name="len">The number of bytes.</param>
        public SimpleLookupTable(ECPoint[] points, int off, int len)
        {
            this.points = Copy(points, off, len);
        }

        /// <inheritdoc/>
        public override int Size
        {
            get { return points.Length; }
        }

        /// <inheritdoc/>
        public override ECPoint Lookup(int index)
        {
            throw new NotSupportedException("Constant-time lookup not supported");
        }

        /// <inheritdoc/>
        public override ECPoint LookupVar(int index)
        {
            return points[index];
        }
    }
}
