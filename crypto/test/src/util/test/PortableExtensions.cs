
#if PORTABLE
using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;

namespace Org.BouncyCastle
{
    static class PortableExtensions
    {
        public static void Close(this Stream stream) => stream.Dispose();
        public static void Close(this TextWriter writer) => writer.Dispose();
        public static void Close(this TextReader reader) => reader.Dispose();
        public static void Close(this TcpClient client) => client.Dispose();
    }
}

#endif
