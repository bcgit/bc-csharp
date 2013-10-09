using System.IO;
using System.Collections;
using System;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{

    public class ServerNameList
    {
        protected IList serverNameList;

        /**
         * @param serverNameList a {@link Vector} of {@link ServerName}.
         */
        public ServerNameList(IList serverNameList)
        {
            if (serverNameList == null || serverNameList.Count == 0)
            {
                throw new ArgumentException("'serverNameList' must not be null or empty");
            }

            this.serverNameList = serverNameList;
        }

        /**
         * @return a {@link Vector} of {@link ServerName}.
         */
        public IList List
        {
            get
            {
                return serverNameList;
            }
        }

        /**
         * Encode this {@link ServerNameList} to an {@link Stream}.
         * 
         * @param output
         *            the {@link Stream} to encode to.
         * @throws IOException
         */
        public void Encode(Stream output)
        {
            MemoryStream buf = new MemoryStream();

            for (int i = 0; i < serverNameList.Count; ++i)
            {
                ServerName entry = (ServerName)serverNameList[i];
                entry.Encode(buf);
            }

            TlsUtilities.CheckUint16((short)buf.Length);
            TlsUtilities.WriteUint16((short)buf.Length, output);
            buf.WriteTo(output);
        }

        /**
         * Parse a {@link ServerNameList} from an {@link InputStream}.
         * 
         * @param input
         *            the {@link InputStream} to parse from.
         * @return a {@link ServerNameList} object.
         * @throws IOException
         */
        public static ServerNameList Parse(Stream input)
        {
            int length = TlsUtilities.ReadUint16(input);
            if (length < 1)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            byte[] data = TlsUtilities.ReadFully(length, input);

            MemoryStream buf = new MemoryStream(data);

            var server_name_list = Platform.CreateArrayList();
            while (buf.Length - buf.Position > 0)
            {
                ServerName entry = ServerName.Parse(buf);
                server_name_list.Add(entry);
            }

            return new ServerNameList(server_name_list);
        }
    }

}