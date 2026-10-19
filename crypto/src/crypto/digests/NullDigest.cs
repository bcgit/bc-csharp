using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Digests
{
    /// <summary>A digest that does no hashing: it returns the data it was given, unchanged.</summary>
    public class NullDigest : IDigest
    {
        private readonly MemoryStream bOut = new MemoryStream();

        /// <inheritdoc/>
        public string AlgorithmName
        {
            get { return "NULL"; }
        }

        /// <inheritdoc/>
        public int GetByteLength()
        {
            // TODO Is this okay?
            return 0;
        }

        /// <inheritdoc/>
        public int GetDigestSize()
        {
            return Convert.ToInt32(bOut.Length);
        }

        /// <inheritdoc/>
        public void Update(byte b)
        {
            bOut.WriteByte(b);
        }

        /// <inheritdoc/>
        public void BlockUpdate(byte[] inBytes, int inOff, int len)
        {
            bOut.Write(inBytes, inOff, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            bOut.Write(input);
        }
#endif

        /// <inheritdoc/>
        public int DoFinal(byte[] outBytes, int outOff)
        {
            try
            {
                byte[] data = bOut.GetBuffer();
                int length = Convert.ToInt32(bOut.Length);

                Array.Copy(data, 0, outBytes, outOff, length);

                return length;
            }
            finally
            {
                Reset();
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public int DoFinal(Span<byte> output)
        {
            try
            {
                byte[] data = bOut.GetBuffer();
                int length = Convert.ToInt32(bOut.Length);

                data.AsSpan(0, length).CopyTo(output);

                return length;
            }
            finally
            {
                Reset();
            }
        }
#endif

        /// <inheritdoc/>
        public void Reset()
        {
            bOut.SetLength(0);
        }
    }
}
