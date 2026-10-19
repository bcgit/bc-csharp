using System;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>A Definite length BIT STRING</summary>
    public class DLBitString
        : DerBitString
    {
        /// <summary>Create a new <see cref="DLBitString"/>.</summary>
        /// <param name="data">The data.</param>
        /// <param name="padBits">The pad bits.</param>
        public DLBitString(byte data, int padBits)
            : base(data, padBits)
        {
        }

        /// <summary>Create a new <see cref="DLBitString"/>.</summary>
        /// <param name="data">The data.</param>
        public DLBitString(byte[] data)
            : this(data, 0)
        {
        }

        /// <summary>Create a new <see cref="DLBitString"/>.</summary>
        /// <param name="data">The data.</param>
        /// <param name="padBits">The pad bits.</param>
        public DLBitString(byte[] data, int padBits)
            : base(data, padBits)
        {
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Create a new <see cref="DLBitString"/>.</summary>
        /// <param name="data">The data.</param>
        public DLBitString(ReadOnlySpan<byte> data)
            : this(data, 0)
        {
        }

        /// <summary>Create a new <see cref="DLBitString"/>.</summary>
        /// <param name="data">The data.</param>
        /// <param name="padBits">The pad bits.</param>
        public DLBitString(ReadOnlySpan<byte> data, int padBits)
            : base(data, padBits)
        {
        }
#endif

        /// <summary>Create a new <see cref="DLBitString"/>.</summary>
        /// <param name="namedBits">The named bits.</param>
        public DLBitString(int namedBits)
            : base(namedBits)
        {
        }

        /// <summary>Create a new <see cref="DLBitString"/>.</summary>
        /// <param name="obj">The object.</param>
        public DLBitString(Asn1Encodable obj)
            : this(obj.GetDerEncoded(), 0)
        {
        }

        internal DLBitString(byte[] contents, bool check)
            : base(contents, check)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncoding(encoding);

            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.BitString, m_contents);
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            return new PrimitiveEncoding(tagClass, tagNo, m_contents);
        }
    }
}
