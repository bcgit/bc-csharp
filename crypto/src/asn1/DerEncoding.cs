using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Asn1
{
    internal abstract class DerEncoding
        : IAsn1Encoding, IComparable<DerEncoding>
    {
        protected internal readonly int m_tagClass;
        protected internal readonly int m_tagNo;

        protected internal DerEncoding(int tagClass, int tagNo)
        {
            Debug.Assert((tagClass & Asn1Tags.Private) == tagClass);
            Debug.Assert(tagNo >= 0);
            m_tagClass = tagClass;
            m_tagNo = tagNo;
        }

        protected internal abstract int CompareLengthAndContents(DerEncoding other);

        public int CompareTo(DerEncoding other)
        {
            Debug.Assert(other != null);
            if (other == null)
                return 1;
            if (m_tagClass != other.m_tagClass)
                return m_tagClass - other.m_tagClass;
            if (m_tagNo != other.m_tagNo)
                return m_tagNo - other.m_tagNo;
            return CompareLengthAndContents(other);
        }

        public abstract void Encode(Asn1OutputStream asn1Out);

        public abstract int GetLength();
    }
}
