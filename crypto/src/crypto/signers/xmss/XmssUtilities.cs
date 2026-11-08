using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss
{
    /// <summary>Utils for XMSS implementation.</summary>
    internal static class XmssUtilities
    {
        /// <summary>
        /// The floor of the logarithm base 2 of <paramref name="n"/> - RFC 8391 sec. 3.1.1's lg() at both places
        /// WOTS+ asks for it.
        /// </summary>
        /// <remarks>Defined for <paramref name="n"/> of 1 or more, which is all WOTS+ passes.</remarks>
        internal static int Log2(int n) => Integers.BitLength(n) - 1;

        /// <summary>
        /// Convert int/long to n-byte array - RFC 8391 sec. 2.4's toByte(x, y).
        /// </summary>
        /// <remarks>
        /// <paramref name="value"/> is taken as unsigned, so a <paramref name="sizeInByte"/> under 8 keeps its low
        /// <paramref name="sizeInByte"/> bytes and one of 8 or more left-pads with zeros.
        /// </remarks>
        /// <param name="value">int/long value.</param>
        /// <param name="sizeInByte">Size of byte array in byte, at least 1.</param>
        /// <returns>int/long as big-endian byte array of size <paramref name="sizeInByte"/>.</returns>
        internal static byte[] ToBytesBigEndian(long value, int sizeInByte)
        {
            byte[] output = new byte[sizeInByte];
            int len = System.Math.Min(sizeInByte, 8);
            Pack.UInt64_To_BE_Low((ulong)value, output, sizeInByte - len, len);
            return output;
        }

        /// <summary>
        /// Return <paramref name="value"/> once it is confirmed to be <paramref name="size"/> bytes long, or a
        /// freshly allocated all-zero array of that size if <paramref name="value"/> is null.
        /// </summary>
        internal static byte[] ValidateOrAllocate(byte[] value, int size, string name)
        {
            if (value == null)
                return new byte[size];

            return ValidateSize(value, size, name);
        }

        /// <summary>
        /// The size check on its own, for a field that is required rather than optional.
        /// </summary>
        /// <remarks>
        /// Absent is not a case here the way it is in <see cref="ValidateOrAllocate"/>: where the caller is
        /// importing a value rather than filling in a key it is building, allocating for a null would substitute
        /// an all-zero value silently, so null is rejected.
        /// </remarks>
        /// <param name="value">the value to check.</param>
        /// <param name="size">the size it has to be.</param>
        /// <param name="name">what to call it in a message.</param>
        internal static byte[] ValidateSize(byte[] value, int size, string name)
        {
            if (value == null)
                throw new ArgumentNullException(name);
            if (value.Length != size)
                throw new ArgumentException("size of " + name + " needs to be equal to size of digest");

            return value;
        }

        /// <summary>Compares two 2d-byte arrays.</summary>
        /// <param name="a">2d-byte array 1.</param>
        /// <param name="b">2d-byte array 2.</param>
        /// <returns>true if all values in 2d-byte array are equal false else.</returns>
        internal static bool AreEqual(byte[][] a, byte[][] b)
        {
            if (Arrays.IsNullOrContainsNull(a) || Arrays.IsNullOrContainsNull(b))
                throw new ArgumentNullException(null, "a or b == null");

            for (int i = 0; i < a.Length; i++)
            {
                if (!Arrays.AreEqual(a[i], b[i]))
                    return false;
            }
            return true;
        }

        /// <summary>Check whether an index is within the leaves of a tree of the given height.</summary>
        /// <remarks>
        /// Only the upper bound is answered as a boolean. A negative index is not reported false but raised as an
        /// <see cref="InvalidOperationException"/>, because the index of a signature that arrived from somewhere
        /// else is read out of its encoding as a signed value.
        /// </remarks>
        /// <param name="height">Height of binary tree.</param>
        /// <param name="index">Index to validate.</param>
        /// <returns>true if the index is below the tree's leaf count, false if it is at or above it.</returns>
        /// <exception cref="InvalidOperationException">if the index is negative.</exception>
        internal static bool IsIndexValid(int height, long index)
        {
            if (index < 0)
                throw new InvalidOperationException("index must not be negative");

            return index < (1L << height);
        }

        internal static int GetLeafIndex(long index, int xmssTreeHeight) =>
            (int)(index & ((1L << xmssTreeHeight) - 1L));

        internal static int CalculateTau(int index, int height)
        {
            int tau = 0;
            for (int i = 0; i < height; i++)
            {
                if (((index >> i) & 1) == 0)
                {
                    tau = i;
                    break;
                }
            }
            return tau;
        }

        /// <summary>
        /// Encode a BDS traversal state in the versioned <see cref="BdsStateCodec"/> form, with its checksum bound
        /// to the public seed of the key it belongs to.
        /// </summary>
        /// <param name="obj">the state to encode.</param>
        /// <param name="publicSeed">the owning key's public seed, or null to bind nothing.</param>
        /// <returns>the encoding.</returns>
        /// <exception cref="ArgumentException">if <paramref name="obj"/> is not a BDS state.</exception>
        /// <exception cref="IOException">if the state is not one the codec can write.</exception>
        internal static byte[] Serialize(object obj, byte[] publicSeed)
        {
            if (obj is Bds bds)
                return BdsStateCodec.Encode(bds, publicSeed);

            // XMSS^MT: the BDS state map is encoded here too, once it exists.

            throw new ArgumentException(
                "unsupported BDS state type: " + (obj != null ? obj.GetType().FullName : "null"));
        }

        /// <summary>Decode a BDS state whose checksum was bound to nothing.</summary>
        internal static object Deserialize(byte[] data, Type type) => Deserialize(data, type, null);

        /// <summary>
        /// Decode a BDS traversal state, checking its checksum against the public seed of the key it belongs to.
        /// </summary>
        /// <remarks>
        /// Only the versioned <see cref="BdsStateCodec"/> form is read. bc-java also falls back to reading state
        /// that Java object serialization wrote, through a class-filtering <c>ObjectInputStream</c>; that format
        /// has no .NET reader and is not ported, so anything without a codec magic is refused here.
        /// </remarks>
        /// <param name="data">the encoded state.</param>
        /// <param name="type">the type of state expected: <see cref="Bds"/>.</param>
        /// <param name="publicSeed">the owning key's public seed, or null if nothing was bound.</param>
        /// <returns>the decoded state, of type <paramref name="type"/>.</returns>
        /// <exception cref="IOException">if the data is not an encoding of that type of state.</exception>
        internal static object Deserialize(byte[] data, Type type, byte[] publicSeed)
        {
            BdsStateCodec.CheckEncodingSize(data);
            if (BdsStateCodec.IsBdsStateEncoding(data))
            {
                if (type != typeof(Bds))
                    throw new IOException("unexpected BDS state encoding");

                return BdsStateCodec.DecodeBds(data, publicSeed);
            }
            if (BdsStateCodec.IsBdsStateMapEncoding(data))
            {
                // XMSS^MT: a state map is decoded here once it exists; until then nothing asks for one.
                throw new IOException("unexpected BDS state map encoding");
            }

            throw new IOException("unrecognized BDS state encoding");
        }
    }
}
