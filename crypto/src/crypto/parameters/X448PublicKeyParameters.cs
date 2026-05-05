using System;
using System.IO;

using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// X448 public key (RFC 7748). Holds the 56-byte u-coordinate of the peer's curve point. The
    /// encoding is stored verbatim; validation of the point is performed during scalar multiplication
    /// in the agreement primitive.
    /// </summary>
    public sealed class X448PublicKeyParameters
        : AsymmetricKeyParameter
    {
        /// <summary>Length in bytes of an X448 public key encoding (56).</summary>
        public static readonly int KeySize = X448.PointSize;

        private readonly byte[] data = new byte[KeySize];

        /// <summary>Construct from a 56-byte buffer holding the encoded u-coordinate.</summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>.</exception>
        public X448PublicKeyParameters(byte[] buf)
            : this(Validate(buf), 0)
        {
        }

        /// <summary>Construct from <paramref name="buf"/> at <paramref name="off"/>; reads
        /// <see cref="KeySize"/> bytes.</summary>
        public X448PublicKeyParameters(byte[] buf, int off)
            : base(false)
        {
            Array.Copy(buf, off, data, 0, KeySize);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Construct from a span holding the encoded u-coordinate.</summary>
        /// <exception cref="ArgumentException">If <paramref name="buf"/> length differs from
        /// <see cref="KeySize"/>.</exception>
        public X448PublicKeyParameters(ReadOnlySpan<byte> buf)
            : base(false)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            buf.CopyTo(data);
        }
#endif

        /// <summary>Read the 56-byte encoded u-coordinate from <paramref name="input"/>.</summary>
        /// <exception cref="EndOfStreamException">If the stream ends before <see cref="KeySize"/>
        /// bytes have been read.</exception>
        public X448PublicKeyParameters(Stream input)
            : base(false)
        {
            if (KeySize != Streams.ReadFully(input, data))
                throw new EndOfStreamException("EOF encountered in middle of X448 public key");
        }

        /// <summary>
        /// Write the 56-byte encoded u-coordinate into <paramref name="buf"/> at <paramref name="off"/>.
        /// </summary>
        public void Encode(byte[] buf, int off)
        {
            Array.Copy(data, 0, buf, off, KeySize);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Write the 56-byte encoded u-coordinate into the supplied span.</summary>
        public void Encode(Span<byte> buf)
        {
            data.CopyTo(buf);
        }
#endif

        /// <summary>Return a fresh copy of the 56-byte encoded u-coordinate.</summary>
        public byte[] GetEncoded()
        {
            return Arrays.Clone(data);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlySpan<byte> DataSpan => data;

        internal ReadOnlyMemory<byte> DataMemory => data;
#endif

        private static byte[] Validate(byte[] buf)
        {
            if (buf.Length != KeySize)
                throw new ArgumentException("must have length " + KeySize, nameof(buf));

            return buf;
        }
    }
}
