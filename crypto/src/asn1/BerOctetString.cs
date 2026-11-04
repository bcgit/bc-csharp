using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>ASN.1 OCTET STRING with BER (possibly constructed) encoding.</summary>
    public class BerOctetString
        : DerOctetString
    {
        /// <summary>The empty BER octet string.</summary>
        public static new readonly BerOctetString Empty = new BerOctetString(EmptyOctets);

        /// <summary>Create a BER octet string from its contents, copying them.</summary>
        /// <param name="contents">The contents.</param>
        /// <returns>The new octet string.</returns>
        public static new BerOctetString FromContents(byte[] contents) =>
            InternalFromContents(contents ?? throw new ArgumentNullException(nameof(contents)));

        /// <summary>
        /// Create a BER octet string from its contents, copying them, or return null if the contents are null.
        /// </summary>
        /// <param name="contents">The contents, or null.</param>
        /// <returns>The new octet string, or null.</returns>
        public static new BerOctetString FromContentsOptional(byte[] contents) =>
            contents == null ? null : InternalFromContents(contents);

        /// <summary>Create a BER octet string by concatenating the octet strings in a sequence.</summary>
        /// <param name="seq">The sequence of octet strings.</param>
        /// <returns>The new octet string.</returns>
        public static BerOctetString FromSequence(Asn1Sequence seq) => new BerOctetString(seq.MapElements(GetInstance));

        /// <summary>Create a BER octet string that uses the given contents array without copying it.</summary>
        /// <param name="contents">The contents, which must not be modified afterwards.</param>
        /// <returns>The new octet string.</returns>
        public static new BerOctetString WithContents(byte[] contents) =>
            InternalWithContents(contents ?? throw new ArgumentNullException(nameof(contents)));

        /// <summary>
        /// Create a BER octet string that uses the given contents array without copying it, or return null if the
        /// contents are null.
        /// </summary>
        /// <param name="contents">The contents, or null; they must not be modified afterwards.</param>
        /// <returns>The new octet string, or null.</returns>
        public static new BerOctetString WithContentsOptional(byte[] contents) =>
            contents == null ? null : InternalWithContents(contents);

        internal static byte[] FlattenOctetStrings(Asn1OctetString[] octetStrings)
        {
            int count = octetStrings.Length;
            switch (count)
            {
            case 0:
                return EmptyOctets;
            case 1:
                return octetStrings[0].contents;
            default:
            {
                int totalOctets = 0;
                for (int i = 0; i < count; ++i)
                {
                    totalOctets += octetStrings[i].contents.Length;
                }

                // Every byte is written below before the array is returned.
#if NET5_0_OR_GREATER
                byte[] str = GC.AllocateUninitializedArray<byte>(totalOctets);
#else
                byte[] str = new byte[totalOctets];
#endif
                int pos = 0;
                for (int i = 0; i < count; ++i)
                {
                    byte[] octets = octetStrings[i].contents;
                    Array.Copy(octets, 0, str, pos, octets.Length);
                    pos += octets.Length;
                }

                // Guards the uninitialized allocation above: never return a partially written array.
                if (pos != totalOctets)
                    throw new InvalidOperationException("flattened octet string length mismatch");

                return str;
            }
            }
        }

        internal static new BerOctetString InternalFromContents(byte[] contents) =>
            contents.Length < 1 ? Empty : new BerOctetString(Arrays.InternalCopyBuffer(contents));

        internal static new BerOctetString InternalWithContents(byte[] contents) =>
            contents.Length < 1 ? Empty : new BerOctetString(contents);

        private readonly Asn1OctetString[] m_elements;

        /// <summary>Create a new <see cref="BerOctetString"/>.</summary>
        /// <param name="contents">The contents.</param>
        public BerOctetString(byte[] contents)
            : this(contents, null)
        {
        }

        /// <summary>Create a new <see cref="BerOctetString"/>.</summary>
        /// <param name="elements">The elements.</param>
        public BerOctetString(Asn1OctetString[] elements)
            : this(FlattenOctetStrings(elements), elements)
        {
        }

        /// <summary>Create a new <see cref="BerOctetString"/>.</summary>
        /// <param name="contents">The contents.</param>
        /// <param name="segmentLimit">The segment limit.</param>
        [Obsolete("Use version without segmentLimit (which is ignored anyway)")]
        public BerOctetString(byte[] contents, int segmentLimit)
            : this(contents)
        {
        }

        /// <summary>Create a new <see cref="BerOctetString"/>.</summary>
        /// <param name="elements">The elements.</param>
        /// <param name="segmentLimit">The segment limit.</param>
        [Obsolete("Use version without segmentLimit (which is ignored anyway)")]
        public BerOctetString(Asn1OctetString[] elements, int segmentLimit)
            : this(elements)
        {
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal BerOctetString(ReadOnlySpan<byte> contents)
            : base(contents)
        {
            m_elements = null;
        }
#endif

        private BerOctetString(byte[] contents, Asn1OctetString[] elements)
            : base(contents)
        {
            m_elements = elements;
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.GetEncoding(encoding);

            if (m_elements == null)
                return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.OctetString, contents);

            return new ConstructedILEncoding(Asn1Tags.Universal, Asn1Tags.OctetString,
                Asn1OutputStream.GetContentsEncodings(encoding, m_elements));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingBer != encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            if (m_elements == null)
                return new PrimitiveEncoding(tagClass, tagNo, contents);

            return new ConstructedILEncoding(tagClass, tagNo,
                Asn1OutputStream.GetContentsEncodings(encoding, m_elements));
        }
    }
}
