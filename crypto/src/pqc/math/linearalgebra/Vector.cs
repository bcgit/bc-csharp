using System;

namespace Org.BouncyCastle.Pqc.Math.LinearAlgebra
{
    /**
 * This abstract class defines vectors. It holds the length of vector.
 */
    public abstract class Vector
    {

        /**
         * the length of this vector
         */
        protected int length;

        /**
         * @return the length of this vector
         */
        public int GetLength()
        {
            return length;
        }

        /**
         * @return this vector as byte array
         */
        public abstract byte[] GetEncoded();

        /**
         * Return whether this is the zero vector (i.e., all elements are zero).
         *
         * @return <tt>true</tt> if this is the zero vector, <tt>false</tt>
         *         otherwise
         */
        public abstract bool IsZero();

        /**
         * Add another vector to this vector.
         *
         * @param addend the other vector
         * @return <tt>this + addend</tt>
         */
        public abstract Vector Add(Vector addend);

        /**
         * Multiply this vector with a permutation.
         *
         * @param p the permutation
         * @return <tt>this*p = p*this</tt>
         */
        public abstract Vector Multiply(Permutation p);

        /**
         * Check if the given object is equal to this vector.
         *
         * @param other vector
         * @return the result of the comparison
         */
        public abstract bool Equals(Object other);

    }
}
