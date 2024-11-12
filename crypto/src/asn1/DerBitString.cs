using System;
using System.Diagnostics;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class DerBitString
		: DerStringBase, Asn1BitStringParser
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(DerBitString), Asn1Tags.BitString) { }

            internal override Asn1Object FromImplicitPrimitive(DerOctetString octetString)
            {
                return CreatePrimitive(octetString.GetOctets());
            }

            internal override Asn1Object FromImplicitConstructed(Asn1Sequence sequence)
            {
                return sequence.ToAsn1BitString();
            }
        }

        internal static readonly byte[] EmptyOctetsContents = new byte[]{ 0x00 };

        private static readonly char[] table
			= { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

		public static DerBitString GetInstance(object obj)
		{
            if (obj == null)
                return null;

			if (obj is DerBitString derBitString)
				return derBitString;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is DerBitString converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return GetInstance(FromByteArray(bytes));
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct BIT STRING from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj));
		}

        public static DerBitString GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
            return (DerBitString)Meta.Instance.GetContextInstance(obj, isExplicit);
        }

        public static DerBitString GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DerBitString existing)
                return existing;

            return null;
        }

        public static DerBitString GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (DerBitString)Meta.Instance.GetTagged(taggedObject, declaredExplicit);
        }

        internal readonly byte[] m_contents;

        public DerBitString(byte data, int padBits)
        {
            if (padBits > 7 || padBits < 0)
                throw new ArgumentException("pad bits cannot be greater than 7 or less than 0", nameof(padBits));

            m_contents = new byte[]{ (byte)padBits, data };
        }

        public DerBitString(byte[] data)
            : this(data, 0)
        {
        }

        /**
		 * @param data the octets making up the bit string.
		 * @param padBits the number of extra bits at the end of the string.
		 */
        public DerBitString(byte[] data, int padBits)
		{
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (padBits < 0 || padBits > 7)
                throw new ArgumentException("must be in the range 0 to 7", nameof(padBits));
            if (data.Length == 0 && padBits != 0)
                throw new ArgumentException("if 'data' is empty, 'padBits' must be 0");

            m_contents = Arrays.Prepend(data, (byte)padBits);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public DerBitString(ReadOnlySpan<byte> data)
            : this(data, 0)
        {
        }

        public DerBitString(ReadOnlySpan<byte> data, int padBits)
        {
            if (padBits < 0 || padBits > 7)
                throw new ArgumentException("must be in the range 0 to 7", nameof(padBits));
            if (data.IsEmpty && padBits != 0)
                throw new ArgumentException("if 'data' is empty, 'padBits' must be 0");

            m_contents = Arrays.Prepend(data, (byte)padBits);
        }
#endif

        public DerBitString(int namedBits)
        {
            if (namedBits == 0)
            {
                m_contents = EmptyOctetsContents;
                return;
            }

            int bits = 32 - Integers.NumberOfLeadingZeros(namedBits);
            int bytes = (bits + 7) / 8;
            Debug.Assert(0 < bytes && bytes <= 4);

            byte[] data = new byte[1 + bytes];

            for (int i = 1; i < bytes; i++)
            {
                data[i] = (byte)namedBits;
                namedBits >>= 8;
            }

            Debug.Assert((namedBits & 0xFF) != 0);
            data[bytes] = (byte)namedBits;

            int padBits = 0;
            while ((namedBits & (1 << padBits)) == 0)
            {
                ++padBits;
            }

            Debug.Assert(padBits < 8);
            data[0] = (byte)padBits;

            m_contents = data;
        }

        public DerBitString(IAsn1Convertible obj)
            : this(obj.ToAsn1Object())
        {
        }

        public DerBitString(Asn1Encodable obj)
            : this(contents: GetDerContents(obj), check: false)
        {
        }

        internal DerBitString(byte[] contents, bool check)
        {
            if (check)
            {
                if (null == contents)
                    throw new ArgumentNullException(nameof(contents));
                if (contents.Length < 1)
                    throw new ArgumentException("cannot be empty", nameof(contents));

                int padBits = contents[0];
                if (padBits > 0)
                {
                    if (contents.Length < 2)
                        throw new ArgumentException("zero length data with non-zero pad bits", nameof(contents));
                    if (padBits > 7)
                        throw new ArgumentException("pad bits cannot be greater than 7 or less than 0",
                            nameof(contents));
                }
            }

            m_contents = contents;
        }

        /**
         * Return the octets contained in this BIT STRING, checking that this BIT STRING really
         * does represent an octet aligned string. Only use this method when the standard you are
         * following dictates that the BIT STRING will be octet aligned.
         *
         * @return a copy of the octet aligned data.
         */
        public virtual byte[] GetOctets()
        {
            CheckOctetAlignment();
            return Arrays.CopyOfRange(m_contents, 1, m_contents.Length);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal ReadOnlyMemory<byte> GetOctetsMemory()
        {
            CheckOctetAlignment();
            return m_contents.AsMemory(1);
        }

        internal ReadOnlySpan<byte> GetOctetsSpan()
        {
            CheckOctetAlignment();
            return m_contents.AsSpan(1);
        }
#endif

        public virtual byte[] GetBytes()
		{
            if (m_contents.Length == 1)
                return Asn1OctetString.EmptyOctets;

            int padBits = m_contents[0];
            byte[] rv = Arrays.CopyOfRange(m_contents, 1, m_contents.Length);
            // DER requires pad bits be zero
            rv[rv.Length - 1] &= (byte)(0xFF << padBits);
            return rv;
        }

        public virtual int PadBits => m_contents[0];

		/**
		 * @return the value of the bit string as an int (truncating if necessary)
		 */
        public virtual int IntValue
		{
			get
			{
                int value = 0, end = System.Math.Min(5, m_contents.Length - 1);
                for (int i = 1; i < end; ++i)
                {
                    value |= (int)m_contents[i] << (8 * (i - 1));
                }
                if (1 <= end && end < 5)
                {
                    int padBits = m_contents[0];
                    byte der = (byte)(m_contents[end] & (0xFF << padBits));
                    value |= (int)der << (8 * (end - 1));
                }
                return value;
            }
		}

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            int padBits = m_contents[0];
            if (padBits != 0)
            {
                int last = m_contents.Length - 1;
                byte lastBer = m_contents[last];
                byte lastDer = (byte)(lastBer & (0xFF << padBits));

                if (lastBer != lastDer)
                    return new PrimitiveEncodingSuffixed(Asn1Tags.Universal, Asn1Tags.BitString, m_contents, lastDer);
            }

            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.BitString, m_contents);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            int padBits = m_contents[0];
            if (padBits != 0)
            {
                int last = m_contents.Length - 1;
                byte lastBer = m_contents[last];
                byte lastDer = (byte)(lastBer & (0xFF << padBits));

                if (lastBer != lastDer)
                    return new PrimitiveEncodingSuffixed(tagClass, tagNo, m_contents, lastDer);
            }

            return new PrimitiveEncoding(tagClass, tagNo, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDer()
        {
            int padBits = m_contents[0];
            if (padBits != 0)
            {
                int last = m_contents.Length - 1;
                byte lastBer = m_contents[last];
                byte lastDer = (byte)(lastBer & (0xFF << padBits));

                if (lastBer != lastDer)
                    return new PrimitiveDerEncodingSuffixed(Asn1Tags.Universal, Asn1Tags.BitString, m_contents, lastDer);
            }

            return new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.BitString, m_contents);
        }

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            int padBits = m_contents[0];
            if (padBits != 0)
            {
                int last = m_contents.Length - 1;
                byte lastBer = m_contents[last];
                byte lastDer = (byte)(lastBer & (0xFF << padBits));

                if (lastBer != lastDer)
                    return new PrimitiveDerEncodingSuffixed(tagClass, tagNo, m_contents, lastDer);
            }

            return new PrimitiveDerEncoding(tagClass, tagNo, m_contents);
        }

        protected override int Asn1GetHashCode()
		{
            if (m_contents.Length < 2)
                return 1;

            int padBits = m_contents[0];
            int last = m_contents.Length - 1;

            byte lastDer = (byte)(m_contents[last] & (0xFF << padBits));

            int hc = Arrays.GetHashCode(m_contents, 0, last);
            hc *= 257;
            hc ^= lastDer;
            return hc;
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
		{
            DerBitString that = asn1Object as DerBitString;
            if (null == that)
                return false;

            byte[] thisContents = this.m_contents, thatContents = that.m_contents;

            int length = thisContents.Length;
            if (thatContents.Length != length)
                return false;
            if (length == 1)
                return true;

            int last = length - 1;
            for (int i = 0; i < last; ++i)
            {
                if (thisContents[i] != thatContents[i])
                    return false;
            }

            int padBits = thisContents[0];
            byte thisLastDer = (byte)(thisContents[last] & (0xFF << padBits));
            byte thatLastDer = (byte)(thatContents[last] & (0xFF << padBits));

            return thisLastDer == thatLastDer;
        }

        public Stream GetBitStream() => GetMemoryStream();

        public Stream GetOctetStream() => GetOctetMemoryStream();

        internal MemoryStream GetOctetMemoryStream()
        {
            CheckOctetAlignment();
            return GetMemoryStream();
        }

        private MemoryStream GetMemoryStream() => new MemoryStream(m_contents, 1, m_contents.Length - 1, false);

        public Asn1BitStringParser Parser => this;

        public override string GetString()
		{
			byte[] str = GetDerEncoded();

            StringBuilder buffer = new StringBuilder(1 + str.Length * 2);
            buffer.Append('#');

            for (int i = 0; i != str.Length; i++)
			{
				uint u8 = str[i];
				buffer.Append(table[u8 >> 4]);
				buffer.Append(table[u8 & 0xF]);
			}

			return buffer.ToString();
		}

        private void CheckOctetAlignment()
        {
            if (m_contents[0] != 0x00)
                throw new IOException("expected octet-aligned bitstring, but found padBits: " + m_contents[0]);
        }

        internal static DerBitString CreatePrimitive(byte[] contents)
		{
            int length = contents.Length;
            if (length < 1)
                throw new ArgumentException("truncated BIT STRING detected", nameof(contents));

            int padBits = contents[0];
            if (padBits > 0)
            {
                if (padBits > 7 || length < 2)
                    throw new ArgumentException("invalid pad bits detected", nameof(contents));

                byte finalOctet = contents[length - 1];
                if (finalOctet != (byte)(finalOctet & (0xFF << padBits)))
                    return new DLBitString(contents, false);
            }

            return new DerBitString(contents, false);
		}

        private static byte[] GetDerContents(Asn1Encodable obj)
        {
            var contents = obj.GetEncoded(Der, preAlloc: 1, postAlloc: 0);
            contents[0] = 0x00;
            return contents;
        }
    }
}
