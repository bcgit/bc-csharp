using System;
using System.Text;

namespace Org.BouncyCastle.Crypto
{
    public class PasswordConverter
        : ICharToByteConverter
    {
        private readonly string name;
        private readonly Func<char[], byte[]> converterFunction;

        public PasswordConverter(string name, Func<char[], byte[]> converterFunction)
        {
            this.name = name;
            this.converterFunction = converterFunction;
        }

        public byte[] Convert(char[] password)
        {
            return converterFunction.Invoke(password);
        }

        public string GetName()
        {
            return name;
        }

        public readonly static ICharToByteConverter ASCII = new PasswordConverter("ASCII", PbeParametersGenerator.Pkcs5PasswordToBytes);

        public readonly static ICharToByteConverter UTF8 = new PasswordConverter("UTF8", PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes);

        public readonly static ICharToByteConverter PKCS12 = new PasswordConverter("PKCS12", PbeParametersGenerator.Pkcs12PasswordToBytes);

        public readonly static ICharToByteConverter UTF32 = new PasswordConverter("UTF32", Encoding.UTF32.GetBytes);

        public readonly static ICharToByteConverter Unicode = new PasswordConverter("Unicode", Encoding.Unicode.GetBytes);

        public readonly static ICharToByteConverter BigEndianUnicode = new PasswordConverter("BigEndianUnicode", Encoding.BigEndianUnicode.GetBytes);

#if NET6_0_OR_GREATER
        public readonly static ICharToByteConverter Latin1 = new PasswordConverter("Latin1", Encoding.Latin1.GetBytes);
#endif
    }
}