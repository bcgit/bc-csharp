using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Pqc.Math.LinearAlgebra
{
    public class IntUtils
    {

        /**
         * Default constructor (private).
         */
        private IntUtils()
        {
            // empty
        }

        /**
         * Compare two int arrays. No null checks are performed.
         *
         * @param left  the first int array
         * @param right the second int array
         * @return the result of the comparison
         */
        public static bool Equals(int[] left, int[] right)
        {
            return Arrays.AreEqual(left, right);
        }

        /**
         * Return a clone of the given int array. No null checks are performed.
         *
         * @param array the array to clone
         * @return the clone of the given array
         */
        public static int[] Clone(int[] array)
        {
            return Arrays.Clone(array);
        }

        /**
         * Fill the given int array with the given value.
         *
         * @param array the array
         * @param value the value
         */
        public static void Fill(int[] array, int value)
        {
            Arrays.Fill(array, value);
        }

        /**
         * Sorts this array of integers according to the Quicksort algorithm. After
         * calling this method this array is sorted in ascending order with the
         * smallest integer taking position 0 in the array.
         * <p>
         * This implementation is based on the quicksort algorithm as described in
         * <code>Data Structures In Java</code> by Thomas A. Standish, Chapter 10,
         * ISBN 0-201-30564-X.
         *
         * @param source the array of integers that needs to be sorted.
         */
        public static void Quicksort(int[] source)
        {
            Quicksort(source, 0, source.Length - 1);
        }

        /**
         * Sort a subarray of a source array. The subarray is specified by its start
         * and end index.
         *
         * @param source the int array to be sorted
         * @param left   the start index of the subarray
         * @param right  the end index of the subarray
         */
        public static void Quicksort(int[] source, int left, int right)
        {
            if (right > left)
            {
                int index = Partition(source, left, right, right);
                Quicksort(source, left, index - 1);
                Quicksort(source, index + 1, right);
            }
        }

        /**
         * Split a subarray of a source array into two partitions. The left
         * partition contains elements that have value less than or equal to the
         * pivot element, the right partition contains the elements that have larger
         * value.
         *
         * @param source     the int array whose subarray will be splitted
         * @param left       the start position of the subarray
         * @param right      the end position of the subarray
         * @param pivotIndex the index of the pivot element inside the array
         * @return the new index of the pivot element inside the array
         */
        private static int Partition(int[] source, int left, int right,
                                     int pivotIndex)
        {

            int pivot = source[pivotIndex];
            source[pivotIndex] = source[right];
            source[right] = pivot;

            int index = left;
            int tmp = 0;
            for (int i = left; i < right; i++)
            {
                if (source[i] <= pivot)
                {
                    tmp = source[index];
                    source[index] = source[i];
                    source[i] = tmp;
                    index++;
                }
            }

            tmp = source[index];
            source[index] = source[right];
            source[right] = tmp;

            return index;
        }

        /**
         * Generates a subarray of a given int array.
         *
         * @param input -
         *              the input int array
         * @param start -
         *              the start index
         * @param end   -
         *              the end index
         * @return a subarray of <tt>input</tt>, ranging from <tt>start</tt> to
         *         <tt>end</tt>
         */
        public static int[] SubArray( int[] input,  int start,
                                      int end)
        {
            int[] result = new int[end - start];
            Array.Copy(input, start, result, 0, end - start);
            return result;
        }

        /**
         * @param input an int array
         * @return a human readable form of the given int array
         */
        public static String ToString(int[] input)
        {
            String result = "";
            for (int i = 0; i < input.Length; i++)
            {
                result += input[i] + " ";
            }
            return result;
        }
    }
}
