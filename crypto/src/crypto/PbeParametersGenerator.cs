using System;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto
{
    /**
     * base class for all Password Based Encyrption (PBE) parameter generator classes.
     */
    public abstract class PbeParametersGenerator
    {
        protected byte[] mPassword;
        protected byte[] mSalt;
        protected int mIterationCount;

        /**
         * base constructor.
         */
        protected PbeParametersGenerator()
        {
        }

        /**
         * initialise the PBE generator.
         *
         * @param password the password converted into bytes (see below).
         * @param salt the salt to be mixed with the password.
         * @param iterationCount the number of iterations the "mixing" function
         * is to be applied for.
         */
        public virtual void Init(byte[] password, byte[] salt, int iterationCount)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));
            if (salt == null)
                throw new ArgumentNullException(nameof(salt));

            this.mPassword = Arrays.Clone(password);
            this.mSalt = Arrays.Clone(salt);
            this.mIterationCount = iterationCount;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void Init(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterationCount)
        {
            this.mPassword = password.ToArray();
            this.mSalt = salt.ToArray();
            this.mIterationCount = iterationCount;
        }
#endif

        public virtual byte[] Password => Arrays.Clone(mPassword);

        public virtual byte[] Salt => Arrays.Clone(mSalt);

        /**
         * return the iteration count.
         *
         * @return the iteration count.
         */
        public virtual int IterationCount => mIterationCount;

        public abstract ICipherParameters GenerateDerivedParameters(string algorithm, int keySize);
        public abstract ICipherParameters GenerateDerivedParameters(string algorithm, int keySize, int ivSize);

        /**
         * Generate derived parameters for a key of length keySize, specifically
         * for use with a MAC.
         *
         * @param keySize the length, in bits, of the key required.
         * @return a parameters object representing a key.
         */
        public abstract ICipherParameters GenerateDerivedMacParameters(int keySize);

        /**
         * converts a password to a byte array according to the scheme in
         * Pkcs5 (ascii, no padding)
         *
         * @param password a character array representing the password.
         * @return a byte array representing the password.
         */
        public static byte[] Pkcs5PasswordToBytes(char[] password)
        {
            if (password == null || password.Length < 1)
                return Array.Empty<byte>();

            return Strings.ToByteArray(password);
        }

        /**
         * converts a password to a byte array according to the scheme in
         * PKCS5 (UTF-8, no padding)
         *
         * @param password a character array representing the password.
         * @return a byte array representing the password.
         */
        public static byte[] Pkcs5PasswordToUtf8Bytes(char[] password)
        {
            if (password == null || password.Length < 1)
                return Array.Empty<byte>();

            return Strings.ToUtf8ByteArray(password);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static byte[] Pkcs5PasswordToBytes(ReadOnlySpan<char> password) => Strings.ToByteArray(password);

        public static byte[] Pkcs5PasswordToUtf8Bytes(ReadOnlySpan<char> password) => Strings.ToUtf8ByteArray(password);
#endif

        /**
         * converts a password to a byte array according to the scheme in
         * Pkcs12 (unicode, big endian, 2 zero pad bytes at the end).
         *
         * @param password a character array representing the password.
         * @return a byte array representing the password.
         */
        public static byte[] Pkcs12PasswordToBytes(char[] password) =>
            Pkcs12PasswordToBytes(password, wrongPkcs12Zero: false);

        public static byte[] Pkcs12PasswordToBytes(char[] password, bool wrongPkcs12Zero)
        {
            if (password == null || password.Length < 1)
                return wrongPkcs12Zero ? new byte[2] : Array.Empty<byte>();

            // 2 pad bytes.
            byte[] bytes = new byte[Encoding.BigEndianUnicode.GetByteCount(password) + 2];
            Encoding.BigEndianUnicode.GetBytes(password, 0, password.Length, bytes, 0);
            return bytes;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static byte[] Pkcs12PasswordToBytes(ReadOnlySpan<char> password) =>
            Pkcs12PasswordToBytes(password, wrongPkcs12Zero: false);

        public static byte[] Pkcs12PasswordToBytes(ReadOnlySpan<char> password, bool wrongPkcs12Zero)
        {
            if (password.IsEmpty)
                return wrongPkcs12Zero ? new byte[2] : Array.Empty<byte>();

            // 2 pad bytes.
            byte[] bytes = new byte[Encoding.BigEndianUnicode.GetByteCount(password) + 2];
            Encoding.BigEndianUnicode.GetBytes(password, bytes);
            return bytes;
        }
#endif
    }
}
