using System;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /*  The BLAKE2 cryptographic hash function was designed by Jean-
     Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian
     Winnerlein.
   
     Reference Implementation and Description can be found at: https://blake2.net/      
     Internet Draft: https://tools.ietf.org/html/draft-saarinen-blake2-02

     This implementation does not support the Tree Hashing Mode. 
 
       For unkeyed hashing, developers adapting BLAKE2 to ASN.1 - based
       message formats SHOULD use the OID tree at x = 1.3.6.1.4.1.1722.12.2.

             Algorithm     | Target | Collision | Hash | Hash ASN.1 |
                Identifier |  Arch  |  Security |  nn  | OID Suffix |
            ---------------+--------+-----------+------+------------+
             id-blake2b160 | 64-bit |   2**80   |  20  |   x.1.20   |
             id-blake2b256 | 64-bit |   2**128  |  32  |   x.1.32   |
             id-blake2b384 | 64-bit |   2**192  |  48  |   x.1.48   |
             id-blake2b512 | 64-bit |   2**256  |  64  |   x.1.64   |
            ---------------+--------+-----------+------+------------+
     */

    /// <summary>
    /// Implementation of the cryptographic hash function Blake2b. 
    /// BLAKE2b is optimized for 64-bit platforms and produces digests of any size
    /// between 1 and 64 bytes.
    /// </summary>
    /// 
    /// <remarks>
    /// <para>
    /// Blake2b offers a built-in keying mechanism to be used directly
    /// for authentication ("Prefix-MAC") rather than a HMAC construction.
    /// </para>
    /// <para>
    /// Blake2b offers a built-in support for a salt for randomized hashing
    /// and a personal string for defining a unique hash function for each application.
    /// </para>
    /// </remarks>
    public sealed class Blake2bDigest
        : IDigest
    {
        // Blake2b Initialization Vector:
        private static readonly ulong[] blake2b_IV =
            // Produced from the square root of primes 2, 3, 5, 7, 11, 13, 17, 19.
            // The same as SHA-512 IV.
            {
                0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL,
                0xa54ff53a5f1d36f1UL, 0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
                0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
            };

        // Message word permutations:
        private static readonly byte[,] blake2b_sigma =
        {
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
            { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
            { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
        };

        private const int ROUNDS = 12; // to use for Catenas H'
        private const int BLOCK_LENGTH_BYTES = 128;// bytes

        // General parameters:
        private int digestLength = 64; // 1- 64 bytes
        private int keyLength = 0; // 0 - 64 bytes for keyed hashing for MAC
        private byte[] salt = null;// new byte[16];
        private byte[] personalization = null;// new byte[16];

        // the key
        private byte[] key = null;

        // Tree hashing parameters:
        // Because this class does not implement the Tree Hashing Mode,
        // these parameters can be treated as constants (see init() function)
        /*
	     * private int fanout = 1; // 0-255 private int depth = 1; // 1 - 255
	     * private int leafLength= 0; private long nodeOffset = 0L; private int
	     * nodeDepth = 0; private int innerHashLength = 0;
	     */

        // whenever this buffer overflows, it will be processed
        // in the Compress() function.
        // For performance issues, long messages will not use this buffer.
        private byte[] buffer = null;// new byte[BLOCK_LENGTH_BYTES];
        // Position of last inserted byte:
        private int bufferPos = 0;// a value from 0 up to 128

        private ulong[] internalState = new ulong[16]; // In the Blake2b paper it is
        // called: v
        private ulong[] chainValue = null; // state vector, in the Blake2b paper it
        // is called: h

        private ulong t0 = 0UL; // holds last significant bits, counter (counts bytes)
        private ulong t1 = 0UL; // counter: Length up to 2^128 are supported
        private ulong f0 = 0UL; // finalization flag, for last block: ~0L

        // For Tree Hashing Mode, not used here:
        // private long f1 = 0L; // finalization flag, for last node: ~0L

        /// <summary>
        /// Initializes a new instance of <see cref="Blake2bDigest"/>.
        /// </summary>
        public Blake2bDigest()
            : this(512)
        {
        }

        /// <summary>
        /// Constructs a new instance of <see cref="Blake2bDigest"/> from another <see cref="Blake2bDigest"/>./>.
        /// </summary>
        /// <param name="digest">The original instance of <see cref="Blake2bDigest"/> that is copied.</param>
        public Blake2bDigest(Blake2bDigest digest)
        {
            this.bufferPos = digest.bufferPos;
            this.buffer = Arrays.Clone(digest.buffer);
            this.keyLength = digest.keyLength;
            this.key = Arrays.Clone(digest.key);
            this.digestLength = digest.digestLength;
            this.chainValue = Arrays.Clone(digest.chainValue);
            this.personalization = Arrays.Clone(digest.personalization);
            this.salt = Arrays.Clone(digest.salt);
            this.t0 = digest.t0;
            this.t1 = digest.t1;
            this.f0 = digest.f0;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="Blake2bDigest"/> with a given digest size.
        /// </summary>
        /// <param name="digestSize">Digest size in bits.</param>
        /// <exception cref="ArgumentException"></exception>
        public Blake2bDigest(int digestSize)
        {
            if (digestSize < 8 || digestSize > 512 || digestSize % 8 != 0)
                throw new ArgumentException("BLAKE2b digest bit length must be a multiple of 8 and not greater than 512");

            buffer = new byte[BLOCK_LENGTH_BYTES];
            keyLength = 0;
            this.digestLength = digestSize / 8;
            Init();
        }

        /// <summary>
        /// <para>
        /// Initializes a new instance of <see cref="Blake2bDigest"/> with a key.
        /// </para>
        /// 
        /// Blake2b for authentication ("Prefix-MAC mode").
        /// After calling the <see cref="DoFinal(byte[], int)"/> method, the key will
        /// remain to be used for further computations of this instance.
        /// The key can be cleared using the <see cref="ClearKey"/> method.
        /// </summary>
        /// <param name="key">A key up to 64 bytes or null.</param>
        /// <exception cref="ArgumentException"></exception>
        public Blake2bDigest(byte[] key)
        {
            buffer = new byte[BLOCK_LENGTH_BYTES];
            if (key != null)
            {
                this.key = new byte[key.Length];
                Array.Copy(key, 0, this.key, 0, key.Length);

                if (key.Length > 64)
                    throw new ArgumentException("Keys > 64 are not supported");

                keyLength = key.Length;
                Array.Copy(key, 0, buffer, 0, key.Length);
                bufferPos = BLOCK_LENGTH_BYTES; // zero padding
            }
            digestLength = 64;
            Init();
        }

        /// <summary>
        /// <para>
        /// Initializes a new instance of <see cref="Blake2bDigest"/> with a key, required digest length (in bytes), salt and personalization.
        /// </para>
        /// 
        /// After calling the <see cref="DoFinal(byte[], int)"/> method, the key, the salt and the personalization
        /// will remain and might be used for further computations with this instance.
        /// The key can be overwritten using the <see cref="ClearKey"/> method, the salt (pepper)
        /// can be overwritten using the <see cref="ClearSalt"/> method.
        /// </summary>
        /// <param name="key">A key up to 64 bytes or null.</param>
        /// <param name="digestLength">Digest length from 1 to 64 bytes.</param>
        /// <param name="salt">A 16 bytes or nullable salt.</param>
        /// <param name="personalization">A 16 bytes or null personalization.</param>
        /// <exception cref="ArgumentException"></exception>
        public Blake2bDigest(byte[] key, int digestLength, byte[] salt, byte[] personalization)
        {
            if (digestLength < 1 || digestLength > 64)
                throw new ArgumentException("Invalid digest length (required: 1 - 64)");

            this.digestLength = digestLength;
            this.buffer = new byte[BLOCK_LENGTH_BYTES];

            if (salt != null)
            {
                if (salt.Length != 16)
                    throw new ArgumentException("salt length must be exactly 16 bytes");

                this.salt = new byte[16];
                Array.Copy(salt, 0, this.salt, 0, salt.Length);
            }
            if (personalization != null)
            {
                if (personalization.Length != 16)
                    throw new ArgumentException("personalization length must be exactly 16 bytes");

                this.personalization = new byte[16];
                Array.Copy(personalization, 0, this.personalization, 0, personalization.Length);
            }
            if (key != null)
            {
                if (key.Length > 64)
                    throw new ArgumentException("Keys > 64 are not supported");

                this.key = new byte[key.Length];
                Array.Copy(key, 0, this.key, 0, key.Length);

                keyLength = key.Length;
                Array.Copy(key, 0, buffer, 0, key.Length);
                bufferPos = BLOCK_LENGTH_BYTES; // zero padding
            }
            Init();
        }

        // initialize chainValue
        private void Init()
        {
            if (chainValue == null)
            {
                chainValue = new ulong[8];

                chainValue[0] = blake2b_IV[0] ^ (ulong)(digestLength | (keyLength << 8) | 0x1010000);

                // 0x1010000 = ((fanout << 16) | (depth << 24) | (leafLength <<
                // 32));
                // with fanout = 1; depth = 0; leafLength = 0;
                chainValue[1] = blake2b_IV[1];// ^ nodeOffset; with nodeOffset = 0;
                chainValue[2] = blake2b_IV[2];// ^ ( nodeDepth | (innerHashLength << 8) );
                // with nodeDepth = 0; innerHashLength = 0;

                chainValue[3] = blake2b_IV[3];

                chainValue[4] = blake2b_IV[4];
                chainValue[5] = blake2b_IV[5];
                if (salt != null)
                {
                    chainValue[4] ^= Pack.LE_To_UInt64(salt, 0);
                    chainValue[5] ^= Pack.LE_To_UInt64(salt, 8);
                }

                chainValue[6] = blake2b_IV[6];
                chainValue[7] = blake2b_IV[7];
                if (personalization != null)
                {
                    chainValue[6] ^= Pack.LE_To_UInt64(personalization, 0);
                    chainValue[7] ^= Pack.LE_To_UInt64(personalization, 8);
                }
            }
        }

        private void InitializeInternalState()
        {
            // initialize v:
            Array.Copy(chainValue, 0, internalState, 0, chainValue.Length);
            Array.Copy(blake2b_IV, 0, internalState, chainValue.Length, 4);
            internalState[12] = t0 ^ blake2b_IV[4];
            internalState[13] = t1 ^ blake2b_IV[5];
            internalState[14] = f0 ^ blake2b_IV[6];
            internalState[15] = blake2b_IV[7];// ^ f1 with f1 = 0
        }

        /// <inheritdoc />
        public void Update(byte b)
        {
            // process the buffer if full else add to buffer:
            int remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
            if (remainingLength == 0)
            { // full buffer
                t0 += BLOCK_LENGTH_BYTES;
                if (t0 == 0)
                { // if message > 2^64
                    t1++;
                }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Compress(buffer);
#else
                Compress(buffer, 0);
#endif
                Array.Clear(buffer, 0, buffer.Length);// clear buffer
                buffer[0] = b;
                bufferPos = 1;
            }
            else
            {
                buffer[bufferPos] = b;
                bufferPos++;
            }
        }

        /// <inheritdoc />
        public void BlockUpdate(byte[] message, int offset, int len)
        {
            if (message == null || len == 0)
                return;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            BlockUpdate(message.AsSpan(offset, len));
#else
            int remainingLength = 0; // left bytes of buffer

            if (bufferPos != 0)
            { // commenced, incomplete buffer

                // complete the buffer:
                remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
                if (remainingLength < len)
                { // full buffer + at least 1 byte
                    Array.Copy(message, offset, buffer, bufferPos, remainingLength);
                    t0 += BLOCK_LENGTH_BYTES;
                    if (t0 == 0)
                    { // if message > 2^64
                        t1++;
                    }
                    Compress(buffer, 0);
                    bufferPos = 0;
                    Array.Clear(buffer, 0, buffer.Length);// clear buffer
                }
                else
                {
                    Array.Copy(message, offset, buffer, bufferPos, len);
                    bufferPos += len;
                    return;
                }
            }

            // process blocks except last block (also if last block is full)
            int messagePos;
            int blockWiseLastPos = offset + len - BLOCK_LENGTH_BYTES;
            for (messagePos = offset + remainingLength; messagePos < blockWiseLastPos; messagePos += BLOCK_LENGTH_BYTES)
            { // block wise 128 bytes
                // without buffer:
                t0 += BLOCK_LENGTH_BYTES;
                if (t0 == 0)
                {
                    t1++;
                }
                Compress(message, messagePos);
            }

            // fill the buffer with left bytes, this might be a full block
            Array.Copy(message, messagePos, buffer, 0, offset + len - messagePos);
            bufferPos += offset + len - messagePos;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc />
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (input.IsEmpty)
                return;

            int remainingLength = 0; // left bytes of buffer

            if (bufferPos != 0)
            { // commenced, incomplete buffer

                // complete the buffer:
                remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
                if (remainingLength < input.Length)
                { // full buffer + at least 1 byte
                    input[..remainingLength].CopyTo(buffer.AsSpan(bufferPos));
                    t0 += BLOCK_LENGTH_BYTES;
                    if (t0 == 0)
                    { // if message > 2^64
                        t1++;
                    }
                    Compress(buffer);
                    bufferPos = 0;
                    Array.Clear(buffer, 0, buffer.Length);// clear buffer
                }
                else
                {
                    input.CopyTo(buffer.AsSpan(bufferPos));
                    bufferPos += input.Length;
                    return;
                }
            }

            // process blocks except last block (also if last block is full)
            int messagePos;
            int blockWiseLastPos = input.Length - BLOCK_LENGTH_BYTES;
            for (messagePos = remainingLength; messagePos < blockWiseLastPos; messagePos += BLOCK_LENGTH_BYTES)
            { // block wise 128 bytes
                // without buffer:
                t0 += BLOCK_LENGTH_BYTES;
                if (t0 == 0)
                {
                    t1++;
                }
                Compress(input[messagePos..]);
            }

            // fill the buffer with left bytes, this might be a full block
            input[messagePos..].CopyTo(buffer.AsSpan());
            bufferPos += input.Length - messagePos;
        }
#endif

        /// <summary>Close the digest, producing the final digest value.</summary>
        /// <remarks>
        ///  The <see cref="DoFinal(byte[], int)"/> call leaves the digest reset. 
        ///  Key, salt and personal string remain.
        /// </remarks>
        /// <param name="output">The byte array the digest is to be copied into.</param>
        /// <param name="outOffset">The offset into the byte array the digest is to start at.</param>
        /// <returns>The number of bytes written.</returns>
        public int DoFinal(byte[] output, int outOffset)
        {
            Check.OutputLength(output, outOffset, digestLength, "output buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(output.AsSpan(outOffset));
#else
            f0 = 0xFFFFFFFFFFFFFFFFUL;
            t0 += (ulong)bufferPos;
            if (bufferPos > 0 && t0 == 0)
            {
                t1++;
            }
            Compress(buffer, 0);
            Array.Clear(buffer, 0, buffer.Length);// Holds eventually the key if input is null
            Array.Clear(internalState, 0, internalState.Length);

            int full = digestLength >> 3, partial = digestLength & 7;
            Pack.UInt64_To_LE(chainValue, 0, full, output, outOffset);
            if (partial > 0)
            {
                byte[] bytes = new byte[8];
                Pack.UInt64_To_LE(chainValue[full], bytes, 0);
                Array.Copy(bytes, 0, output, outOffset + digestLength - partial, partial);
            }

            Array.Clear(chainValue, 0, chainValue.Length);

            Reset();

            return digestLength;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Close the digest, producing the final digest value.</summary>
        /// <remarks>
        ///  The <see cref="DoFinal(Span{byte})"/> call leaves the digest reset. 
        ///  Key, salt and personal string remain.
        /// </remarks>
        /// <param name="output">The span the digest is to be copied into.</param>
        /// <returns>The number of bytes written.</returns>
        public int DoFinal(Span<byte> output)
        {
            Check.OutputLength(output, digestLength, "output buffer too short");

            f0 = 0xFFFFFFFFFFFFFFFFUL;
            t0 += (ulong)bufferPos;
            if (bufferPos > 0 && t0 == 0)
            {
                t1++;
            }
            Compress(buffer);
            Array.Clear(buffer, 0, buffer.Length);// Holds eventually the key if input is null
            Array.Clear(internalState, 0, internalState.Length);

            int full = digestLength >> 3, partial = digestLength & 7;
            Pack.UInt64_To_LE(chainValue.AsSpan(0, full), output);
            if (partial > 0)
            {
                Span<byte> bytes = stackalloc byte[8];
                Pack.UInt64_To_LE(chainValue[full], bytes);
                bytes[..partial].CopyTo(output[(digestLength - partial)..]);
            }

            Array.Clear(chainValue, 0, chainValue.Length);

            Reset();

            return digestLength;
        }
#endif

        /// <summary>
        /// Reset the digest back to it's initial state.
        /// The key, the salt and the personalization will remain for further computations.
        /// </summary>
        public void Reset()
        {
            bufferPos = 0;
            f0 = 0L;
            t0 = 0L;
            t1 = 0L;
            chainValue = null;
            Array.Clear(buffer, 0, buffer.Length);
            if (key != null)
            {
                Array.Copy(key, 0, buffer, 0, key.Length);
                bufferPos = BLOCK_LENGTH_BYTES; // zero padding
            }
            Init();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void Compress(ReadOnlySpan<byte> message)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Blake2b_X86.IsSupported)
            {
                Blake2b_X86.Compress(f0 == ulong.MaxValue, chainValue, message, t0, t1, blake2b_IV);
                return;
            }
#endif
            InitializeInternalState();

            Span<ulong> m = stackalloc ulong[16];
            Pack.LE_To_UInt64(message, m);

            for (int round = 0; round < ROUNDS; round++)
            {
                // G apply to columns of internalState:m[blake2b_sigma[round][2 * blockPos]] /+1
                G(m[blake2b_sigma[round, 0]], m[blake2b_sigma[round, 1]], 0, 4, 8, 12);
                G(m[blake2b_sigma[round, 2]], m[blake2b_sigma[round, 3]], 1, 5, 9, 13);
                G(m[blake2b_sigma[round, 4]], m[blake2b_sigma[round, 5]], 2, 6, 10, 14);
                G(m[blake2b_sigma[round, 6]], m[blake2b_sigma[round, 7]], 3, 7, 11, 15);
                // G apply to diagonals of internalState:
                G(m[blake2b_sigma[round, 8]], m[blake2b_sigma[round, 9]], 0, 5, 10, 15);
                G(m[blake2b_sigma[round, 10]], m[blake2b_sigma[round, 11]], 1, 6, 11, 12);
                G(m[blake2b_sigma[round, 12]], m[blake2b_sigma[round, 13]], 2, 7, 8, 13);
                G(m[blake2b_sigma[round, 14]], m[blake2b_sigma[round, 15]], 3, 4, 9, 14);
            }

            // update chain values:
            for (int offset = 0; offset < chainValue.Length; offset++)
            {
                chainValue[offset] = chainValue[offset] ^ internalState[offset] ^ internalState[offset + 8];
            }
        }
#else
        private void Compress(byte[] message, int messagePos)
        {
            InitializeInternalState();

            ulong[] m = new ulong[16];
            Pack.LE_To_UInt64(message, messagePos, m);

            for (int round = 0; round < ROUNDS; round++)
            {
                // G apply to columns of internalState:m[blake2b_sigma[round][2 * blockPos]] /+1
                G(m[blake2b_sigma[round,0]], m[blake2b_sigma[round,1]], 0, 4, 8, 12);
                G(m[blake2b_sigma[round,2]], m[blake2b_sigma[round,3]], 1, 5, 9, 13);
                G(m[blake2b_sigma[round,4]], m[blake2b_sigma[round,5]], 2, 6, 10, 14);
                G(m[blake2b_sigma[round,6]], m[blake2b_sigma[round,7]], 3, 7, 11, 15);
                // G apply to diagonals of internalState:
                G(m[blake2b_sigma[round,8]], m[blake2b_sigma[round,9]], 0, 5, 10, 15);
                G(m[blake2b_sigma[round,10]], m[blake2b_sigma[round,11]], 1, 6, 11, 12);
                G(m[blake2b_sigma[round,12]], m[blake2b_sigma[round,13]], 2, 7, 8, 13);
                G(m[blake2b_sigma[round,14]], m[blake2b_sigma[round,15]], 3, 4, 9, 14);
            }

            // update chain values:
            for (int offset = 0; offset < chainValue.Length; offset++)
            {
                chainValue[offset] = chainValue[offset] ^ internalState[offset] ^ internalState[offset + 8];
            }
        }
#endif

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void G(ulong m1, ulong m2, int posA, int posB, int posC, int posD)
        {
            internalState[posA] = internalState[posA] + internalState[posB] + m1;
            internalState[posD] = Rotr64(internalState[posD] ^ internalState[posA], 32);
            internalState[posC] = internalState[posC] + internalState[posD];
            internalState[posB] = Rotr64(internalState[posB] ^ internalState[posC], 24); // replaces 25 of BLAKE
            internalState[posA] = internalState[posA] + internalState[posB] + m2;
            internalState[posD] = Rotr64(internalState[posD] ^ internalState[posA], 16);
            internalState[posC] = internalState[posC] + internalState[posD];
            internalState[posB] = Rotr64(internalState[posB] ^ internalState[posC], 63); // replaces 11 of BLAKE
        }

        private static ulong Rotr64(ulong x, int rot)
        {
            return x >> rot | x << -rot;
        }

        /// <inheritdoc />
        public string AlgorithmName => "BLAKE2b";

        /// <inheritdoc />
        public int GetDigestSize()
        {
            return digestLength;
        }

        /// <summary>
        ///  Return the size in bytes of the internal buffer the digest applies it's compression 
        ///  function to.
        ///  </summary>
        /// <returns>The byte length of the digests internal buffer.</returns>
        public int GetByteLength()
        {
            return BLOCK_LENGTH_BYTES;
        }

        /// <summary>
        /// Clears the key.
        /// </summary>
        public void ClearKey()
        {
            if (key != null)
            {
                Array.Clear(key, 0, key.Length);
                Array.Clear(buffer, 0, buffer.Length);
            }
        }

        /// <summary>
        /// Clears the salt (pepper).
        /// </summary>
        public void ClearSalt()
        {
            if (salt != null)
            {
                Array.Clear(salt, 0, salt.Length);
            }
        }
    }
}
