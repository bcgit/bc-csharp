using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Asn1
{
    internal class PrimitiveDerEncodingSuffixed
        : DerEncoding
    {
        private readonly byte[] m_contentsOctets;
        private readonly byte m_contentsSuffix;

        internal PrimitiveDerEncodingSuffixed(int tagClass, int tagNo, byte[] contentsOctets, byte contentsSuffix)
            : base(tagClass, tagNo)
        {
            Debug.Assert(contentsOctets != null);
            Debug.Assert(contentsOctets.Length > 0);
            m_contentsOctets = contentsOctets;
            m_contentsSuffix = contentsSuffix;
        }

        protected internal override int CompareLengthAndContents(DerEncoding other)
        {
            if (other is PrimitiveDerEncodingSuffixed suff)
            {
                return CompareSuffixed(this.m_contentsOctets, this.m_contentsSuffix,
                                       suff.m_contentsOctets, suff.m_contentsSuffix);
            }
            else if (other is PrimitiveDerEncoding that)
            {
                int length = that.m_contentsOctets.Length;
                if (length == 0)
                    return this.m_contentsOctets.Length;

                return CompareSuffixed(this.m_contentsOctets, this.m_contentsSuffix,
                                       that.m_contentsOctets, that.m_contentsOctets[length - 1]);
            }
            else
            {
                throw new InvalidOperationException();
            }
        }

        public override void Encode(Asn1OutputStream asn1Out)
        {
            asn1Out.WriteIdentifier(m_tagClass, m_tagNo);
            asn1Out.WriteDL(m_contentsOctets.Length);
            asn1Out.Write(m_contentsOctets, 0, m_contentsOctets.Length - 1);
            asn1Out.WriteByte(m_contentsSuffix);
        }

        public override int GetLength()
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(m_tagNo, m_contentsOctets.Length);
        }

        private static int CompareSuffixed(byte[] octetsA, byte suffixA, byte[] octetsB, byte suffixB)
        {
            Debug.Assert(octetsA.Length > 0);
            Debug.Assert(octetsB.Length > 0);

            int length = octetsA.Length;
            if (length != octetsB.Length)
                return length - octetsB.Length;

            int last = length - 1;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int c = octetsA.AsSpan(0, last).SequenceCompareTo(
                    octetsB.AsSpan(0, last));
            if (c != 0)
                return c;
#else
            for (int i = 0; i < last; i++)
            {
                byte ai = octetsA[i], bi = octetsB[i];
                if (ai != bi)
                    return ai - bi;
            }
#endif

            return suffixA - suffixB;
        }
    }
}
