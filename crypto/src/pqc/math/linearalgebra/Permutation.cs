using Org.BouncyCastle.Security;
using System;

namespace Org.BouncyCastle.Pqc.Math.LinearAlgebra
{
    /**
  * This class implements permutations of the set {0,1,...,n-1} for some given n
  * &gt; 0, i.e., ordered sequences containing each number <tt>m</tt> (<tt>0 &lt;=
  * m &lt; n</tt>)
  * once and only once.
  */
    public class Permutation
    {

        /**
         * perm holds the elements of the permutation vector, i.e. <tt>[perm(0),
         * perm(1), ..., perm(n-1)]</tt>
         */
        private int[] perm;

        /**
         * Create the identity permutation of the given size.
         *
         * @param n the size of the permutation
         */
        public Permutation(int n)
        {
            if (n <= 0)
            {
                throw new ArgumentException("invalid length");
            }

            perm = new int[n];
            for (int i = n - 1; i >= 0; i--)
            {
                perm[i] = i;
            }
        }

        /**
         * Create a permutation using the given permutation vector.
         *
         * @param perm the permutation vector
         */
        public Permutation(int[] perm)
        {
            if (!IsPermutation(perm))
            {
                throw new ArgumentException(
                    "array is not a permutation vector");
            }

            this.perm = IntUtils.Clone(perm);
        }

        /**
         * Create a random permutation of the given size.
         *
         * @param n  the size of the permutation
         * @param sr the source of randomness
         */
        public Permutation(int n, SecureRandom sr)
        {
            if (n <= 0)
            {
                throw new ArgumentException("invalid length");
            }

            perm = new int[n];

            int[] help = new int[n];
            for (int i = 0; i < n; i++)
            {
                help[i] = i;
            }

            int k = n;
            for (int j = 0; j < n; j++)
            {
                int i = RandUtils.NextInt(sr, k);
                k--;
                perm[j] = help[i];
                help[i] = help[k];
            }
        }


        /**
         * @return the permutation vector <tt>(perm(0),perm(1),...,perm(n-1))</tt>
         */
        public int[] GetVector()
        {
            return IntUtils.Clone(perm);
        }

        /**
         * Compute the inverse permutation <tt>P<sup>-1</sup></tt>.
         *
         * @return <tt>this<sup>-1</sup></tt>
         */
        public Permutation ComputeInverse()
        {
            Permutation result = new Permutation(perm.Length);
            for (int i = perm.Length - 1; i >= 0; i--)
            {
                result.perm[perm[i]] = i;
            }
            return result;
        }

        /**
         * Compute the product of this permutation and another permutation.
         *
         * @param p the other permutation
         * @return <tt>this * p</tt>
         */
        public Permutation RightMultiply(Permutation p)
        {
            if (p.perm.Length != perm.Length)
            {
                throw new ArgumentException("length mismatch");
            }
            Permutation result = new Permutation(perm.Length);
            for (int i = perm.Length - 1; i >= 0; i--)
            {
                result.perm[i] = perm[p.perm[i]];
            }
            return result;
        }

        /**
         * checks if given object is equal to this permutation.
         * <p>
         * The method returns false whenever the given object is not permutation.
         *
         * @param other -
         *              permutation
         * @return true or false
         */
        public bool equals(Object other)
        {

            if (!(other is Permutation))
        {
                return false;
            }
            Permutation otherPerm = (Permutation)other;

            return IntUtils.Equals(perm, otherPerm.perm);
        }

        /**
         * @return a human readable form of the permutation
         */
        public String ToString()
        {
            String result = "[" + perm[0];
            for (int i = 1; i < perm.Length; i++)
            {
                result += ", " + perm[i];
            }
            result += "]";
            return result;
        }

        /**
         * Check that the given array corresponds to a permutation of the set
         * <tt>{0, 1, ..., n-1}</tt>.
         *
         * @param perm permutation vector
         * @return true if perm represents an n-permutation and false otherwise
         */
        private bool IsPermutation(int[] perm)
        {
            int n = perm.Length;
            bool[] onlyOnce = new bool[n];

            for (int i = 0; i < n; i++)
            {
                if ((perm[i] < 0) || (perm[i] >= n) || onlyOnce[perm[i]])
                {
                    return false;
                }
                onlyOnce[perm[i]] = true;
            }

            return true;
        }

    }

}
