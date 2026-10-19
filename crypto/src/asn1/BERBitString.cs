using System;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 BIT STRING with BER (possibly constructed) encoding.</summary>
    public class BerBitString
        : DLBitString
    {
        public static BerBitString FromSequence(Asn1Sequence seq)
        {
            return new BerBitString(seq.MapElements(GetInstance));
        }

        internal static byte[] FlattenBitStrings(DerBitString[] bitStrings)
        {
            int count = bitStrings.Length;
            switch (count)
            {
            case 0:
                // No bits
                return EmptyOctetsContents;
            case 1:
                return bitStrings[0].m_contents;
            default:
            {
                int last = count - 1, totalLength = 0;
                for (int i = 0; i < last; ++i)
                {
                    byte[] elementContents = bitStrings[i].m_contents;
                    if (elementContents[0] != 0)
                        throw new ArgumentException("only the last nested bitstring can have padding",
                            nameof(bitStrings));

                    totalLength += elementContents.Length - 1;
                }

                // Last one can have padding
                byte[] lastElementContents = bitStrings[last].m_contents;
                byte padBits = lastElementContents[0];
                totalLength += lastElementContents.Length;

                // Every byte is written below before the array is returned.
#if NET5_0_OR_GREATER
                byte[] contents = GC.AllocateUninitializedArray<byte>(totalLength);
#else
                byte[] contents = new byte[totalLength];
#endif
                contents[0] = padBits;

                int pos = 1;
                for (int i = 0; i < count; ++i)
                {
                    byte[] elementContents = bitStrings[i].m_contents;
                    int length = elementContents.Length - 1;
                    Array.Copy(elementContents, 1, contents, pos, length);
                    pos += length;
                }

                // Guards the uninitialized allocation above: never return a partially written array.
                if (pos != totalLength)
                    throw new InvalidOperationException("flattened bit string length mismatch");

                return contents;
            }
            }
        }

        private readonly DerBitString[] elements;

        /// <summary>Create a new <see cref="BerBitString"/>.</summary>
        /// <param name="data">The data.</param>
        /// <param name="padBits">The pad bits.</param>
        public BerBitString(byte data, int padBits)
            : base(data, padBits)
        {
            this.elements = null;
        }

        /// <summary>Create a new <see cref="BerBitString"/>.</summary>
        /// <param name="data">The data.</param>
        public BerBitString(byte[] data)
            : this(data, 0)
        {
        }

        /// <summary>Create a new <see cref="BerBitString"/>.</summary>
        /// <param name="data">The data.</param>
        /// <param name="padBits">The pad bits.</param>
        public BerBitString(byte[] data, int padBits)
            : base(data, padBits)
        {
            this.elements = null;
        }

        /// <summary>Create a new <see cref="BerBitString"/>.</summary>
        /// <param name="data">The data.</param>
        /// <param name="padBits">The pad bits.</param>
        /// <param name="segmentLimit">The segment limit.</param>
        [Obsolete("Use version without segmentLimit (which is ignored anyway)")]
        public BerBitString(byte[] data, int padBits, int segmentLimit)
            : this(data, padBits)
        {
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Create a new <see cref="BerBitString"/>.</summary>
        /// <param name="data">The data.</param>
        public BerBitString(ReadOnlySpan<byte> data)
            : this(data, 0)
        {
        }

        /// <summary>Create a new <see cref="BerBitString"/>.</summary>
        /// <param name="data">The data.</param>
        /// <param name="padBits">The pad bits.</param>
        public BerBitString(ReadOnlySpan<byte> data, int padBits)
            : base(data, padBits)
        {
            this.elements = null;
        }
#endif

        /// <summary>Create a new <see cref="BerBitString"/>.</summary>
        /// <param name="namedBits">The named bits.</param>
        public BerBitString(int namedBits)
            : base(namedBits)
        {
            this.elements = null;
        }

        /// <summary>Create a new <see cref="BerBitString"/>.</summary>
        /// <param name="obj">The object.</param>
        public BerBitString(Asn1Encodable obj)
            : this(obj.GetDerEncoded(), 0)
        {
        }

        /// <summary>Create a new <see cref="BerBitString"/>.</summary>
        /// <param name="elements">The elements.</param>
        public BerBitString(DerBitString[] elements)
            : base(FlattenBitStrings(elements), false)
        {
            this.elements = elements;
        }

        /// <summary>Create a new <see cref="BerBitString"/>.</summary>
        /// <param name="elements">The elements.</param>
        /// <param name="segmentLimit">The segment limit.</param>
        [Obsolete("Use version without segmentLimit (which is ignored anyway)")]
        public BerBitString(DerBitString[] elements, int segmentLimit)
            : this(elements)
        {
        }

        internal BerBitString(byte[] contents, bool check)
            : base(contents, check)
        {
            this.elements = null;
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.GetEncoding(encoding);

            if (null == elements)
                return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.BitString, m_contents);

            return new ConstructedILEncoding(Asn1Tags.Universal, Asn1Tags.BitString,
                Asn1OutputStream.GetContentsEncodings(encoding, elements));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            if (null == elements)
                return new PrimitiveEncoding(tagClass, tagNo, m_contents);

            return new ConstructedILEncoding(tagClass, tagNo,
                Asn1OutputStream.GetContentsEncodings(encoding, elements));
        }
    }
}
