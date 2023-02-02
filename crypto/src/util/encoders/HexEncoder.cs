using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.Encoders
{
    public class HexEncoder
        : IEncoder
    {
        protected readonly byte[] encodingTable =
        {
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
            (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
        };

        /*
         * set up the decoding table.
         */
        protected readonly byte[] decodingTable = new byte[128];

        protected void InitialiseDecodingTable()
        {
            Arrays.Fill(decodingTable, (byte)0xff);

            for (int i = 0; i < encodingTable.Length; i++)
            {
                decodingTable[encodingTable[i]] = (byte)i;
            }

            decodingTable['A'] = decodingTable['a'];
            decodingTable['B'] = decodingTable['b'];
            decodingTable['C'] = decodingTable['c'];
            decodingTable['D'] = decodingTable['d'];
            decodingTable['E'] = decodingTable['e'];
            decodingTable['F'] = decodingTable['f'];
        }

        public HexEncoder()
        {
            InitialiseDecodingTable();
        }

        public int Encode(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Encode(inBuf.AsSpan(inOff, inLen), outBuf.AsSpan(outOff));
#else
            int inPos = inOff;
            int inEnd = inOff + inLen;
            int outPos = outOff;

            while (inPos < inEnd)
            {
                uint b = inBuf[inPos++];

                outBuf[outPos++] = encodingTable[b >> 4];
                outBuf[outPos++] = encodingTable[b & 0xF];
            }

            return outPos - outOff;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Encode(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int inPos = 0;
            int inEnd = input.Length;
            int outPos = 0;

            while (inPos < inEnd)
            {
                uint b = input[inPos++];

                output[outPos++] = encodingTable[b >> 4];
                output[outPos++] = encodingTable[b & 0xF];
            }

            return outPos;
        }
#endif

        /**
        * encode the input data producing a Hex output stream.
        *
        * @return the number of bytes produced.
        */
        public int Encode(byte[] buf, int off, int len, Stream outStream)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Encode(buf.AsSpan(off, len), outStream);
#else
            if (len < 0)
                return 0;

            byte[] tmp = new byte[72];
            int remaining = len;
            while (remaining > 0)
            {
                int inLen = System.Math.Min(36, remaining);
                int outLen = Encode(buf, off, inLen, tmp, 0);
                outStream.Write(tmp, 0, outLen);
                off += inLen;
                remaining -= inLen;
            }
            return len * 2;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Encode(ReadOnlySpan<byte> data, Stream outStream)
        {
            Span<byte> tmp = stackalloc byte[72];
            int result = data.Length * 2;
            while (!data.IsEmpty)
            {
                int inLen = System.Math.Min(36, data.Length);
                int outLen = Encode(data[..inLen], tmp);
                outStream.Write(tmp[..outLen]);
                data = data[inLen..];
            }
            return result;
        }
#endif

        private static bool Ignore(char c)
        {
            return c == '\n' || c =='\r' || c == '\t' || c == ' ';
        }

        /**
        * decode the Hex encoded byte data writing it to the given output stream,
        * whitespace characters will be ignored.
        *
        * @return the number of bytes produced.
        */
        public int Decode(byte[] data, int off, int length, Stream outStream)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Decode(data.AsSpan(off, length), outStream);
#else
            byte b1, b2;
            int outLen = 0;
            byte[] buf = new byte[36];
            int bufOff = 0;
            int end = off + length;

            while (end > off)
            {
                if (!Ignore((char)data[end - 1]))
                    break;

                end--;
            }

            int i = off;
            while (i < end)
            {
                while (i < end && Ignore((char)data[i]))
                {
                    i++;
                }

                b1 = decodingTable[data[i++]];

                while (i < end && Ignore((char)data[i]))
                {
                    i++;
                }

                b2 = decodingTable[data[i++]];

                if ((b1 | b2) >= 0x80)
                    throw new IOException("invalid characters encountered in Hex data");

                buf[bufOff++] = (byte)((b1 << 4) | b2);

                if (bufOff == buf.Length)
                {
                    outStream.Write(buf, 0, bufOff);
                    bufOff = 0;
                }

                outLen++;
            }

            if (bufOff > 0)
            {
                outStream.Write(buf, 0, bufOff);
            }

            return outLen;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Decode(ReadOnlySpan<byte> data, Stream outStream)
        {
            byte b1, b2;
            int outLen = 0;
            Span<byte> buf = stackalloc byte[36];
            int bufOff = 0;
            int end = data.Length;

            while (end > 0)
            {
                if (!Ignore((char)data[end - 1]))
                    break;

                end--;
            }

            int i = 0;
            while (i < end)
            {
                while (i < end && Ignore((char)data[i]))
                {
                    i++;
                }

                b1 = decodingTable[data[i++]];

                while (i < end && Ignore((char)data[i]))
                {
                    i++;
                }

                b2 = decodingTable[data[i++]];

                if ((b1 | b2) >= 0x80)
                    throw new IOException("invalid characters encountered in Hex data");

                buf[bufOff++] = (byte)((b1 << 4) | b2);

                if (bufOff == buf.Length)
                {
                    outStream.Write(buf);
                    bufOff = 0;
                }

                outLen++;
            }

            if (bufOff > 0)
            {
                outStream.Write(buf[..bufOff]);
            }

            return outLen;
        }
#endif

        /**
        * decode the Hex encoded string data writing it to the given output stream,
        * whitespace characters will be ignored.
        *
        * @return the number of bytes produced.
        */
        public int DecodeString(string data, Stream outStream)
        {
            byte b1, b2;
            int length = 0;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[36];
#else
            byte[] buf = new byte[36];
#endif
            int bufOff = 0;
            int end = data.Length;

            while (end > 0)
            {
                if (!Ignore(data[end - 1]))
                    break;

                end--;
            }

            int i = 0;
            while (i < end)
            {
                while (i < end && Ignore(data[i]))
                {
                    i++;
                }

                b1 = decodingTable[data[i++]];

                while (i < end && Ignore(data[i]))
                {
                    i++;
                }

                b2 = decodingTable[data[i++]];

                if ((b1 | b2) >= 0x80)
                    throw new IOException("invalid characters encountered in Hex data");

                buf[bufOff++] = (byte)((b1 << 4) | b2);

                if (bufOff == buf.Length)
                {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    outStream.Write(buf);
#else
                    outStream.Write(buf, 0, bufOff);
#endif
                    bufOff = 0;
                }

                length++;
            }

            if (bufOff > 0)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                outStream.Write(buf[..bufOff]);
#else
                outStream.Write(buf, 0, bufOff);
#endif
            }

            return length;
        }

        internal byte[] DecodeStrict(string str, int off, int len)
        {
            if (null == str)
                throw new ArgumentNullException("str");
            if (off < 0 || len < 0 || off > (str.Length - len))
                throw new IndexOutOfRangeException("invalid offset and/or length specified");
            if (0 != (len & 1))
                throw new ArgumentException("a hexadecimal encoding must have an even number of characters", "len");

            int resultLen = len >> 1;
            byte[] result = new byte[resultLen];

            int strPos = off;
            for (int i = 0; i < resultLen; ++i)
            {
                byte b1 = decodingTable[str[strPos++]];
                byte b2 = decodingTable[str[strPos++]];

                if ((b1 | b2) >= 0x80)
                    throw new IOException("invalid characters encountered in Hex data");

                result[i] = (byte)((b1 << 4) | b2);
            }
            return result;
        }
    }
}
