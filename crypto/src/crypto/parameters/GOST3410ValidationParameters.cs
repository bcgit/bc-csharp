using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// The seed and counter used to generate GOST R 34.10-94 domain parameters, so that they can be validated.
    /// </summary>
    public class Gost3410ValidationParameters
    {
        private int x0;
        private int c;
        private long x0L;
        private long cL;

        /// <summary>Create a new <see cref="Gost3410ValidationParameters"/>.</summary>
        /// <param name="x0">The x 0.</param>
        /// <param name="c">The c.</param>
        public Gost3410ValidationParameters(
            int x0,
            int c)
        {
            this.x0 = x0;
            this.c = c;
        }

        /// <summary>Create a new <see cref="Gost3410ValidationParameters"/>.</summary>
        /// <param name="x0L">The x 0 l.</param>
        /// <param name="cL">The c l.</param>
        public Gost3410ValidationParameters(
            long x0L,
            long cL)
        {
            this.x0L = x0L;
            this.cL = cL;
        }

        /// <summary>Gets the c.</summary>
        public int C { get { return c; } }
        /// <summary>Gets the x 0.</summary>
        public int X0 { get { return x0; } }
        /// <summary>Gets the CL.</summary>
        public long CL { get { return cL; } }
        /// <summary>Gets the x 0 l.</summary>
        public long X0L { get { return x0L; } }

        /// <inheritdoc/>
        public override bool Equals(
            object obj)
        {
            Gost3410ValidationParameters other = obj as Gost3410ValidationParameters;

            return other != null
                && other.c == this.c
                && other.x0 == this.x0
                && other.cL == this.cL
                && other.x0L == this.x0L;
        }

        /// <inheritdoc/>
        public override int GetHashCode()
        {
            return c.GetHashCode() ^ x0.GetHashCode() ^ cL.GetHashCode() ^ x0L.GetHashCode();
        }

    }
}
