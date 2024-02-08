namespace Org.BouncyCastle.Crypto
{
    public interface ICharToByteConverter
    {
        /**
         * Return the type of the conversion.
         *
         * @return a type name for the conversion.
         */
        string GetName();

        /**
         * Return a byte encoded representation of the passed in password.
         *
         * @param password the characters to encode.
         * @return a byte encoding of password.
         */
        byte[] Convert(char[] password);
    }

    public static class CharToByteConverterExtensions
    {

        /**
         * Return a byte encoded representation of the passed in password.
         *
         * @param password the string to encode.
         * @return a byte encoding of password.
         */
        public static byte[] Convert(this ICharToByteConverter converter, string password)
        {
            return converter.Convert(password.ToCharArray());
        }
    }
}