using System.IO;

namespace Org.BouncyCastle.Utilities.IO.Compression
{
    using Impl = Utilities.Bzip2;

    internal static class Bzip2
    {
        internal static Stream CompressOutput(Stream stream, bool leaveOpen = false)
        {
            return leaveOpen
                ?   new Impl.CBZip2OutputStreamLeaveOpen(stream)
                :   new Impl.CBZip2OutputStream(stream);
        }

        internal static Stream DecompressInput(Stream stream, bool leaveOpen = false)
        {
            return leaveOpen
                ?   new Impl.CBZip2InputStreamLeaveOpen(stream)
                :   new Impl.CBZip2InputStream(stream);
        }
    }
}
