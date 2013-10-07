using System;
using System.IO;
using Org.BouncyCastle.Utilities;
namespace Org.BouncyCastle.Crypto.Tls
{

    public class ServerName
    {
        protected NameType nameType;
        protected Object name;

        public ServerName(short nameType, Object name)
        {
            if (!IsCorrectType(nameType, name))
            {
                throw new ArgumentException("'name' is not an instance of the correct type");
            }

            this.nameType = (NameType)nameType;
            this.name = name;
        }

        public NameType NameType
        {
            get
            {
                return nameType;
            }
        }

        public Object Name
        {
            get
            {
                return name;
            }
        }

        public String HostName
        {
            get
            {
                if (!IsCorrectType((short)NameType.host_name, name))
                {
                    throw new InvalidOperationException("'name' is not a HostName string");
                }
                return (String)name;
            }
        }

        /**
         * Encode this {@link ServerName} to an {@link Stream}.
         * 
         * @param output
         *            the {@link Stream} to encode to.
         * @throws IOException
         */
        public void Encode(Stream output)
        {
            TlsUtilities.WriteUint8((byte)nameType, output);

            switch (nameType)
            {
                case NameType.host_name:
                    byte[] utf8Encoding = Strings.ToUtf8ByteArray((String)name);
                    if (utf8Encoding.Length < 1)
                    {
                        throw new TlsFatalAlert(AlertDescription.internal_error);
                    }
                    TlsUtilities.WriteOpaque16(utf8Encoding, output);
                    break;
                default:
                    throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        /**
         * Parse a {@link ServerName} from an {@link InputStream}.
         * 
         * @param input
         *            the {@link InputStream} to parse from.
         * @return a {@link ServerName} object.
         * @throws IOException
         */
        public static ServerName Parse(Stream input)
        {
            short name_type = TlsUtilities.ReadUint8(input);
            Object name;

            switch (name_type)
            {
                case (short)NameType.host_name:
                    {
                        byte[] utf8Encoding = TlsUtilities.ReadOpaque16(input);
                        if (utf8Encoding.Length < 1)
                        {
                            throw new TlsFatalAlert(AlertDescription.decode_error);
                        }
                        name = Strings.FromUtf8ByteArray(utf8Encoding);
                        break;
                    }
                default:
                    throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            return new ServerName(name_type, name);
        }

        protected static bool IsCorrectType(short nameType, Object name)
        {
            switch (nameType)
            {
                case (short)NameType.host_name:
                    return name is string;
                default:
                    throw new ArgumentException("'name' is an unsupported value");
            }
        }
    }
}