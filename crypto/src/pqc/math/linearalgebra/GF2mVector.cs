using System;

namespace Org.BouncyCastle.Pqc.Math.LinearAlgebra
{
    /**
 * This class implements vectors over the finite field
 * <tt>GF(2<sup>m</sup>)</tt> for small <tt>m</tt> (i.e.,
 * <tt>1&lt;m&lt;32</tt>). It extends the abstract class {@link Vector}.
 */
public class GF2mVector : Vector
{

    /**
     * the finite field this vector is defined over
     */
    private GF2mField field;

    /**
     * the element array
     */
    private int[] vector;

    /**
     * creates the vector over GF(2^m) of given length and with elements from
     * array v (beginning at the first bit)
     *
     * @param field finite field
     * @param v     array with elements of vector
     */
    public GF2mVector(GF2mField field, byte[] v)
    {
        this.field = new GF2mField(field);

        // decode vector
        int d = 8;
        int count = 1;
        while (field.GetDegree() > d)
        {
            count++;
            d += 8;
        }

        if ((v.Length % count) != 0)
        {
            throw new ArgumentException(
                "Byte array is not an encoded vector over the given finite field.");
        }

        length = v.Length / count;
        vector = new int[length];
        count = 0;
        for (int i = 0; i < vector.Length; i++)
        {
            for (int j = 0; j < d; j += 8)
            {
                vector[i] |= (v[count++] & 0xff) << j;
            }
            if (!field.IsElementOfThisField(vector[i]))
            {
                throw new ArgumentException(
                    "Byte array is not an encoded vector over the given finite field.");
            }
        }
    }

    /**
     * Create a new vector over <tt>GF(2<sup>m</sup>)</tt> of the given
     * length and element array.
     *
     * @param field  the finite field <tt>GF(2<sup>m</sup>)</tt>
     * @param vector the element array
     */
    public GF2mVector(GF2mField field, int[] vector)
    {
        this.field = field;
        length = vector.Length;
        for (int i = vector.Length - 1; i >= 0; i--)
        {
            if (!field.IsElementOfThisField(vector[i]))
            {
                throw new ArithmeticException(
                    "Element array is not specified over the given finite field.");
            }
        }
        this.vector = IntUtils.Clone(vector);
    }

    /**
     * Copy constructor.
     *
     * @param other another {@link GF2mVector}
     */
    public GF2mVector(GF2mVector other)
    {
        field = new GF2mField(other.field);
        length = other.length;
        vector = IntUtils.Clone(other.vector);
    }

    /**
     * @return the finite field this vector is defined over
     */
    public GF2mField GetField()
    {
        return field;
    }

    /**
     * @return int[] form of this vector
     */
    public int[] GetIntArrayForm()
    {
        return IntUtils.Clone(vector);
    }

        /**
         * @return a byte array encoding of this vector
         */
        public override byte[] GetEncoded()
    {
        int d = 8;
        int count = 1;
        while (field.GetDegree() > d)
        {
            count++;
            d += 8;
        }

        byte[] res = new byte[vector.Length * count];
        count = 0;
        for (int i = 0; i < vector.Length; i++)
        {
            for (int j = 0; j < d; j += 8)
            {
                res[count++] = (byte)(Utils.UnsignedRightBitShiftInt(vector[i], j));
            }
        }

        return res;
    }

    /**
     * @return whether this is the zero vector (i.e., all elements are zero)
     */
    public override bool IsZero()
    {
        for (int i = vector.Length - 1; i >= 0; i--)
        {
            if (vector[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * Add another vector to this vector. Method is not yet implemented.
     *
     * @param addend the other vector
     * @return <tt>this + addend</tt>
     * @throws ArithmeticException if the other vector is not defined over the same field as
     * this vector.
     * <p>
     * TODO: implement this method
     */
    public override Vector Add(Vector addend)
    {
        throw new SystemException("not implemented");
    }

    /**
     * Multiply this vector with a permutation.
     *
     * @param p the permutation
     * @return <tt>this*p = p*this</tt>
     */
    public override Vector Multiply(Permutation p)
    {
        int[] pVec = p.GetVector();
        if (length != pVec.Length)
        {
            throw new ArithmeticException(
                "permutation size and vector size mismatch");
        }

        int[] result = new int[length];
        for (int i = 0; i < pVec.Length; i++)
        {
            result[i] = vector[pVec[i]];
        }

        return new GF2mVector(field, result);
    }

    /**
     * Compare this vector with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    public override bool Equals(Object other)
    {

        if (!(other is GF2mVector))
        {
            return false;
        }
        GF2mVector otherVec = (GF2mVector)other;

        if (!field.Equals(otherVec.field))
        {
            return false;
        }

        return IntUtils.Equals(vector, otherVec.vector);
    }

      
    }
}
