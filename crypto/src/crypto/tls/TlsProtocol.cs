using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    public abstract class TlsProtocol
    {
        /**
        * Make sure the Stream is now empty. Fail otherwise.
        *
        * @param is The Stream to check.
        * @throws IOException If is is not empty.
        */
        protected internal static void AssertEmpty(MemoryStream buf)
        {
            if (buf.Position < buf.Length)
                throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        protected internal static IDictionary ReadExtensions(MemoryStream input)
        {
            if (input.Position >= input.Length)
                return null;

            byte[] extBytes = TlsUtilities.ReadOpaque16(input);

            AssertEmpty(input);

            MemoryStream buf = new MemoryStream(extBytes, false);

            // Integer -> byte[]
            IDictionary extensions = Platform.CreateHashtable();

            while (buf.Position < buf.Length)
            {
                int extension_type = TlsUtilities.ReadUint16(buf);
                byte[] extension_data = TlsUtilities.ReadOpaque16(buf);

                /*
                 * RFC 3546 2.3 There MUST NOT be more than one extension of the same type.
                 */
                if (extensions.Contains(extension_type))
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);

                extensions.Add(extension_type, extension_data);
            }

            return extensions;
        }

        protected internal static void WriteExtensions(Stream output, IDictionary extensions)
        {
            MemoryStream buf = new MemoryStream();

            foreach (int extension_type in extensions.Keys)
            {
                byte[] extension_data = (byte[])extensions[extension_type];

                TlsUtilities.CheckUint16(extension_type);
                TlsUtilities.WriteUint16(extension_type, buf);
                TlsUtilities.WriteOpaque16(extension_data, buf);
            }

            byte[] extBytes = buf.ToArray();

            TlsUtilities.WriteOpaque16(extBytes, output);
        }
    }
}
