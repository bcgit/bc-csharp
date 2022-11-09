using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.Encoders
{
    public class Base64Encoder
        : IEncoder
    {
        protected readonly byte[] encodingTable =
        {
            (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G',
            (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N',
            (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U',
            (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z',
            (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
            (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
            (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
            (byte)'v',
            (byte)'w', (byte)'x', (byte)'y', (byte)'z',
            (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6',
            (byte)'7', (byte)'8', (byte)'9',
            (byte)'+', (byte)'/'
        };

        protected byte padding = (byte)'=';

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
        }

        public Base64Encoder()
        {
            InitialiseDecodingTable();
        }

        public int Encode(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Encode(inBuf.AsSpan(inOff, inLen), outBuf.AsSpan(outOff));
#else
            int inPos = inOff;
            int inEnd = inOff + inLen - 2;
            int outPos = outOff;

            while (inPos < inEnd)
            {
                uint a1 = inBuf[inPos++];
                uint a2 = inBuf[inPos++];
                uint a3 = inBuf[inPos++];

                outBuf[outPos++] = encodingTable[(a1 >> 2) & 0x3F];
                outBuf[outPos++] = encodingTable[((a1 << 4) | (a2 >> 4)) & 0x3F];
                outBuf[outPos++] = encodingTable[((a2 << 2) | (a3 >> 6)) & 0x3F];
                outBuf[outPos++] = encodingTable[a3 & 0x3F];
            }

            switch (inLen - (inPos - inOff))
            {
            case 1:
            {
                uint a1 = inBuf[inPos++];

                outBuf[outPos++] = encodingTable[(a1 >> 2) & 0x3F];
                outBuf[outPos++] = encodingTable[(a1 << 4) & 0x3F];
                outBuf[outPos++] = padding;
                outBuf[outPos++] = padding;
                break;
            }
            case 2:
            {
                uint a1 = inBuf[inPos++];
                uint a2 = inBuf[inPos++];

                outBuf[outPos++] = encodingTable[(a1 >> 2) & 0x3F];
                outBuf[outPos++] = encodingTable[((a1 << 4) | (a2 >> 4)) & 0x3F];
                outBuf[outPos++] = encodingTable[(a2 << 2) & 0x3F];
                outBuf[outPos++] = padding;
                break;
            }
            }

            return outPos - outOff;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Encode(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int inPos = 0;
            int inEnd = input.Length - 2;
            int outPos = 0;

            while (inPos < inEnd)
            {
                uint a1 = input[inPos++];
                uint a2 = input[inPos++];
                uint a3 = input[inPos++];

                output[outPos++] = encodingTable[(a1 >> 2) & 0x3F];
                output[outPos++] = encodingTable[((a1 << 4) | (a2 >> 4)) & 0x3F];
                output[outPos++] = encodingTable[((a2 << 2) | (a3 >> 6)) & 0x3F];
                output[outPos++] = encodingTable[a3 & 0x3F];
            }

            switch (input.Length - inPos)
            {
            case 1:
            {
                uint a1 = input[inPos++];

                output[outPos++] = encodingTable[(a1 >> 2) & 0x3F];
                output[outPos++] = encodingTable[(a1 << 4) & 0x3F];
                output[outPos++] = padding;
                output[outPos++] = padding;
                break;
            }
            case 2:
            {
                uint a1 = input[inPos++];
                uint a2 = input[inPos++];

                output[outPos++] = encodingTable[(a1 >> 2) & 0x3F];
                output[outPos++] = encodingTable[((a1 << 4) | (a2 >> 4)) & 0x3F];
                output[outPos++] = encodingTable[(a2 << 2) & 0x3F];
                output[outPos++] = padding;
                break;
            }
            }

            return outPos;
        }
#endif

        /**
        * encode the input data producing a base 64 output stream.
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
                int inLen = System.Math.Min(54, remaining);
                int outLen = Encode(buf, off, inLen, tmp, 0);
                outStream.Write(tmp, 0, outLen);
                off += inLen;
                remaining -= inLen;
            }
            return (len + 2) / 3 * 4;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Encode(ReadOnlySpan<byte> data, Stream outStream)
        {
            Span<byte> tmp = stackalloc byte[72];
            int result = (data.Length + 2) / 3 * 4;
            while (!data.IsEmpty)
            {
                int inLen = System.Math.Min(54, data.Length);
                int outLen = Encode(data[..inLen], tmp);
                outStream.Write(tmp[..outLen]);
                data = data[inLen..];
            }
            return result;
        }
#endif

        private bool Ignore(char c)
        {
            return c == '\n' || c =='\r' || c == '\t' || c == ' ';
        }

        /**
        * decode the base 64 encoded byte data writing it to the given output stream,
        * whitespace characters will be ignored.
        *
        * @return the number of bytes produced.
        */
        public int Decode(byte[] data, int off, int length, Stream outStream)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Decode(data.AsSpan(off, length), outStream);
#else
            byte b1, b2, b3, b4;
            byte[] outBuffer = new byte[54];   // S/MIME standard
            int bufOff = 0;
            int outLen = 0;
            int end = off + length;

            while (end > off)
            {
                if (!Ignore((char)data[end - 1]))
                    break;

                end--;
            }

            int finish = end - 4;
            int i = NextI(data, off, finish);

            while (i < finish)
            {
                b1 = decodingTable[data[i++]];

                i = NextI(data, i, finish);

                b2 = decodingTable[data[i++]];

                i = NextI(data, i, finish);

                b3 = decodingTable[data[i++]];

                i = NextI(data, i, finish);

                b4 = decodingTable[data[i++]];

                if ((b1 | b2 | b3 | b4) >= 0x80)
                    throw new IOException("invalid characters encountered in base64 data");

                outBuffer[bufOff++] = (byte)((b1 << 2) | (b2 >> 4));
                outBuffer[bufOff++] = (byte)((b2 << 4) | (b3 >> 2));
                outBuffer[bufOff++] = (byte)((b3 << 6) | b4);

                if (bufOff == outBuffer.Length)
                {
                    outStream.Write(outBuffer, 0, bufOff);
                    bufOff = 0;
                }

                outLen += 3;

                i = NextI(data, i, finish);
            }

            if (bufOff > 0)
            {
                outStream.Write(outBuffer, 0, bufOff);
            }

            int e0 = NextI(data, i, end);
            int e1 = NextI(data, e0 + 1, end);
            int e2 = NextI(data, e1 + 1, end);
            int e3 = NextI(data, e2 + 1, end);

            outLen += DecodeLastBlock(outStream, (char)data[e0], (char)data[e1], (char)data[e2], (char)data[e3]);

            return outLen;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Decode(ReadOnlySpan<byte> data, Stream outStream)
        {
            byte b1, b2, b3, b4;
            Span<byte> outBuffer = stackalloc byte[54];   // S/MIME standard
            int bufOff = 0;
            int outLen = 0;
            int end = data.Length;

            while (end > 0)
            {
                if (!Ignore((char)data[end - 1]))
                    break;

                end--;
            }

            int finish = end - 4;
            int i = NextI(data, 0, finish);

            while (i < finish)
            {
                b1 = decodingTable[data[i++]];

                i = NextI(data, i, finish);

                b2 = decodingTable[data[i++]];

                i = NextI(data, i, finish);

                b3 = decodingTable[data[i++]];

                i = NextI(data, i, finish);

                b4 = decodingTable[data[i++]];

                if ((b1 | b2 | b3 | b4) >= 0x80)
                    throw new IOException("invalid characters encountered in base64 data");

                outBuffer[bufOff++] = (byte)((b1 << 2) | (b2 >> 4));
                outBuffer[bufOff++] = (byte)((b2 << 4) | (b3 >> 2));
                outBuffer[bufOff++] = (byte)((b3 << 6) | b4);

                if (bufOff == outBuffer.Length)
                {
                    outStream.Write(outBuffer);
                    bufOff = 0;
                }

                outLen += 3;

                i = NextI(data, i, finish);
            }

            if (bufOff > 0)
            {
                outStream.Write(outBuffer[..bufOff]);
            }

            int e0 = NextI(data, i, end);
            int e1 = NextI(data, e0 + 1, end);
            int e2 = NextI(data, e1 + 1, end);
            int e3 = NextI(data, e2 + 1, end);

            outLen += DecodeLastBlock(outStream, (char)data[e0], (char)data[e1], (char)data[e2], (char)data[e3]);

            return outLen;
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private int NextI(ReadOnlySpan<byte> data, int i, int finish)
#else
        private int NextI(byte[] data, int i, int finish)
#endif
        {
            while ((i < finish) && Ignore((char)data[i]))
            {
                i++;
            }
            return i;
        }

        /**
        * decode the base 64 encoded string data writing it to the given output stream,
        * whitespace characters will be ignored.
        *
        * @return the number of bytes produced.
        */
        public int DecodeString(string data, Stream	outStream)
        {
            // Platform Implementation
//			byte[] bytes = Convert.FromBase64String(data);
//			outStream.Write(bytes, 0, bytes.Length);
//			return bytes.Length;

            byte b1, b2, b3, b4;
            int length = 0;

            int end = data.Length;

            while (end > 0)
            {
                if (!Ignore(data[end - 1]))
                    break;

                end--;
            }

            int finish = end - 4;
            int i = NextI(data, 0, finish);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[3];
#endif

            while (i < finish)
            {
                b1 = decodingTable[data[i++]];

                i = NextI(data, i, finish);

                b2 = decodingTable[data[i++]];

                i = NextI(data, i, finish);

                b3 = decodingTable[data[i++]];

                i = NextI(data, i, finish);

                b4 = decodingTable[data[i++]];

                if ((b1 | b2 | b3 | b4) >= 0x80)
                    throw new IOException("invalid characters encountered in base64 data");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                buf[0] = (byte)((b1 << 2) | (b2 >> 4));
                buf[1] = (byte)((b2 << 4) | (b3 >> 2));
                buf[2] = (byte)((b3 << 6) | b4);
                outStream.Write(buf);
#else
                outStream.WriteByte((byte)((b1 << 2) | (b2 >> 4)));
                outStream.WriteByte((byte)((b2 << 4) | (b3 >> 2)));
                outStream.WriteByte((byte)((b3 << 6) | b4));
#endif

                length += 3;

                i = NextI(data, i, finish);
            }

            length += DecodeLastBlock(outStream, data[end - 4], data[end - 3], data[end - 2], data[end - 1]);

            return length;
        }

        private int DecodeLastBlock(
            Stream	outStream,
            char	c1,
            char	c2,
            char	c3,
            char	c4)
        {
            if (c3 == padding)
            {
                if (c4 != padding)
                    throw new IOException("invalid characters encountered at end of base64 data");

                byte b1 = decodingTable[c1];
                byte b2 = decodingTable[c2];

                if ((b1 | b2) >= 0x80)
                    throw new IOException("invalid characters encountered at end of base64 data");

                outStream.WriteByte((byte)((b1 << 2) | (b2 >> 4)));

                return 1;
            }

            if (c4 == padding)
            {
                byte b1 = decodingTable[c1];
                byte b2 = decodingTable[c2];
                byte b3 = decodingTable[c3];

                if ((b1 | b2 | b3) >= 0x80)
                    throw new IOException("invalid characters encountered at end of base64 data");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<byte> buf = stackalloc byte[2] {
                    (byte)((b1 << 2) | (b2 >> 4)),
                    (byte)((b2 << 4) | (b3 >> 2)),
                };
                outStream.Write(buf);
#else
                outStream.WriteByte((byte)((b1 << 2) | (b2 >> 4)));
                outStream.WriteByte((byte)((b2 << 4) | (b3 >> 2)));
#endif

                return 2;
            }

            {
                byte b1 = decodingTable[c1];
                byte b2 = decodingTable[c2];
                byte b3 = decodingTable[c3];
                byte b4 = decodingTable[c4];

                if ((b1 | b2 | b3 | b4) >= 0x80)
                    throw new IOException("invalid characters encountered at end of base64 data");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Span<byte> buf = stackalloc byte[3] {
                    (byte)((b1 << 2) | (b2 >> 4)),
                    (byte)((b2 << 4) | (b3 >> 2)),
                    (byte)((b3 << 6) | b4),
                };
                outStream.Write(buf);
#else
                outStream.WriteByte((byte)((b1 << 2) | (b2 >> 4)));
                outStream.WriteByte((byte)((b2 << 4) | (b3 >> 2)));
                outStream.WriteByte((byte)((b3 << 6) | b4));
#endif

                return 3;
            }
        }

        private int NextI(string data, int i, int finish)
        {
            while ((i < finish) && Ignore(data[i]))
            {
                i++;
            }
            return i;
        }
    }
}
