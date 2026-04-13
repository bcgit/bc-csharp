using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    internal abstract class LimitedInputStream
        : BaseInputStream
    {
        protected readonly Stream m_in;
        private int m_limit;

        internal LimitedInputStream(Stream inStream, int limit)
        {
            m_in = inStream;
            m_limit = limit;
        }

        internal virtual int Limit => m_limit;

        protected void EnableParentEofDetect()
        {
            if (m_in is IndefiniteLengthInputStream indef)
            {
                indef.SetEofOn00(true);
            }
        }
    }
}
