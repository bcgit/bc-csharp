using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    /// <summary>Assembles the byte strings of an LMS encoding, in the order RFC 8554 gives them.</summary>
    public sealed class Composer
    {
        private readonly MemoryStream m_buffer = new MemoryStream();

        private Composer()
        {
        }

        /// <summary>Start composing a message.</summary>
        /// <returns>A new composer.</returns>
        public static Composer Compose() => new Composer();

        /// <summary>Append an unsigned 64-bit value in big-endian form.</summary>
        /// <param name="n">The value.</param>
        /// <returns>This composer.</returns>
        public Composer U64Str(long n)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[8];
            Pack.UInt64_To_BE((ulong)n, buf);
            m_buffer.Write(buf);
#else
            U32Str((int)(n >> 32));
            U32Str((int)n);
#endif
            return this;
        }

        /// <summary>Append an unsigned 32-bit value in big-endian form.</summary>
        /// <param name="n">The value.</param>
        /// <returns>This composer.</returns>
        public Composer U32Str(int n)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[4];
            Pack.UInt32_To_BE((uint)n, buf);
            m_buffer.Write(buf);
#else
            m_buffer.WriteByte((byte)(n >> 24));
            m_buffer.WriteByte((byte)(n >> 16));
            m_buffer.WriteByte((byte)(n >> 8));
            m_buffer.WriteByte((byte)n);
#endif
            return this;
        }

        /// <summary>Append an unsigned 16-bit value in big-endian form.</summary>
        /// <param name="n">The value.</param>
        /// <returns>This composer.</returns>
        public Composer U16Str(int n)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[2];
            Pack.UInt16_To_BE((ushort)n, buf);
            m_buffer.Write(buf);
#else
            n &= 0xFFFF;
            m_buffer.WriteByte((byte)(n >> 8));
            m_buffer.WriteByte((byte)n);
#endif
            return this;
        }

        /// <summary>Append the encodings of several objects.</summary>
        /// <param name="encodable">The objects.</param>
        /// <returns>This composer.</returns>
        public Composer Bytes(IEncodable[] encodable)
        {
            foreach (var e in encodable)
            {
                byte[] encoding = e.GetEncoded();
                m_buffer.Write(encoding, 0, encoding.Length);
            }
            return this;
        }

        /// <summary>Append the encoding of an object.</summary>
        /// <param name="encodable">The object.</param>
        /// <returns>This composer.</returns>
        public Composer Bytes(IEncodable encodable)
        {
            byte[] encoding = encodable.GetEncoded();
            m_buffer.Write(encoding, 0, encoding.Length);
            return this;
        }

        /// <summary>Append zero bytes.</summary>
        /// <param name="v">The value of the padding bytes.</param>
        /// <param name="len">The number of bytes.</param>
        /// <returns>This composer.</returns>
        public Composer Pad(int v, int len)
        {
            for (; len > 0; len--)
            {
                m_buffer.WriteByte((byte)v);
            }
            return this;
        }

        /// <summary>Append several arrays.</summary>
        /// <param name="arrays">The arrays.</param>
        /// <returns>This composer.</returns>
        public Composer Bytes2(byte[][] arrays)
        {
            foreach (byte[] array in arrays)
            {
                m_buffer.Write(array, 0, array.Length);
            }
            return this;
        }

        /// <summary>Append a range of an array of arrays.</summary>
        /// <param name="arrays">The arrays.</param>
        /// <param name="start">The index of the first array to append.</param>
        /// <param name="end">The index after the last array to append.</param>
        /// <returns>This composer.</returns>
        public Composer Bytes2(byte[][] arrays, int start, int end)
        {
            for (int j = start; j < end; ++j)
            {
                m_buffer.Write(arrays[j], 0, arrays[j].Length);
            }
            return this;
        }

        /// <summary>Append an array.</summary>
        /// <param name="array">The array.</param>
        /// <returns>This composer.</returns>
        public Composer Bytes(byte[] array)
        {
            m_buffer.Write(array, 0, array.Length);
            return this;
        }

        /// <summary>Append a range of an array.</summary>
        /// <param name="array">The array.</param>
        /// <param name="start">The index of the first byte.</param>
        /// <param name="len">The number of bytes.</param>
        /// <returns>This composer.</returns>
        public Composer Bytes(byte[] array, int start, int len)
        {
            m_buffer.Write(array, start, len);
            return this;
        }

        /// <summary>Get the composed message.</summary>
        /// <returns>The message.</returns>
        public byte[] Build() => m_buffer.ToArray();

        /// <summary>Feed what has been composed to <paramref name="digest"/> in place of building it.</summary>
        /// <remarks>WriteTo hands the stream's own buffer over, so the encoding is never copied out.</remarks>
        // TODO[lms] Low priority: a composer could write through to the sink as each piece is added, dropping the
        // buffer entirely. Worth measuring first - the encodings are short, and the write-through composer would
        // have to give up PadUntil, which needs the length so far.
        //
        // Further out, a caller holding the whole input at once needs no buffering digest at all, but that is a
        // deeper change than it looks: LmsContext absorbs its prefix at construction and takes the message later,
        // so the input is split before anything could hash it in one go, IDigest has no one-shot entry point, and
        // the implementations buffer per block regardless. The gain would have to come from one-shot platform APIs
        // (net5+), which do not cover the SHAKE parameter sets.
        internal void BuildTo(IDigest digest) => m_buffer.WriteTo(new DigestSink(digest));

        /// <summary>Append padding until the message has the required length.</summary>
        /// <param name="v">The value of the padding bytes.</param>
        /// <param name="requiredLen">The required length.</param>
        /// <returns>This composer.</returns>
        public Composer PadUntil(int v, int requiredLen)
        {
            while (m_buffer.Length < requiredLen)
            {
                m_buffer.WriteByte((byte)v);
            }
            return this;
        }

        /// <summary>Append a boolean as one byte.</summary>
        /// <param name="v">The value.</param>
        /// <returns>This composer.</returns>
        public Composer Boolean(bool v)
        {
            m_buffer.WriteByte((byte)(v ? 1 : 0));
            return this;
        }
    }
}
