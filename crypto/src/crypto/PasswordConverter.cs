namespace Org.BouncyCastle.Crypto
{
    /// <summary>
    /// Standard char[] to byte[] converters for password based derivation algorithms.
    /// </summary>
    public sealed class PasswordConverter
        : ICharToByteConverter
    {
        private delegate byte[] ConverterFunction(char[] password);

        private readonly string m_name;
        private readonly ConverterFunction m_converterFunction;

        private PasswordConverter(string name, ConverterFunction converterFunction)
        {
            m_name = name;
            m_converterFunction = converterFunction;
        }

        public byte[] Convert(char[] password) => m_converterFunction(password);

        public string Name => m_name;

        /// <summary>Do a straight char[] to 8 bit conversion.</summary>
        public readonly static ICharToByteConverter Ascii = new PasswordConverter("ASCII",
            PbeParametersGenerator.Pkcs5PasswordToBytes);

        /// <summary>Do a char[] conversion by producing UTF-8 data.</summary>
        public readonly static ICharToByteConverter Utf8 = new PasswordConverter("UTF8",
            PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes);

        /// <summary>Do char[] to BMP conversion (i.e. 2 bytes per character).</summary>
        public readonly static ICharToByteConverter Pkcs12 = new PasswordConverter("PKCS12",
            PbeParametersGenerator.Pkcs12PasswordToBytes);
    }
}
