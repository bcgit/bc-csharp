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
        /// <summary>The password bytes.</summary>
        protected byte[] mPassword;
        /// <summary>The salt bytes.</summary>
        protected byte[] mSalt;
        /// <summary>The iteration count.</summary>
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
        /// <summary>Initialise the generator with the password, salt and iteration count.</summary>
        /// <param name="password">The password, as bytes.</param>
        /// <param name="salt">The salt.</param>
        /// <param name="iterationCount">The number of iterations the derivation function is to be applied for.</param>
        public virtual void Init(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int iterationCount)
        {
            this.mPassword = password.ToArray();
            this.mSalt = salt.ToArray();
            this.mIterationCount = iterationCount;
        }
#endif

        /// <summary>Gets the password.</summary>
        public virtual byte[] Password => Arrays.Clone(mPassword);

        /// <summary>Gets the salt.</summary>
        public virtual byte[] Salt => Arrays.Clone(mSalt);

        /**
         * return the iteration count.
         *
         * @return the iteration count.
         */
        public virtual int IterationCount => mIterationCount;

        /// <summary>
        /// Generate derived parameters for a key of the given size (and, where given, an initialization vector).
        /// </summary>
        /// <param name="algorithm">The name of the algorithm the key is for.</param>
        /// <param name="keySize">The size of the key, in bits.</param>
        /// <returns>The derived parameters.</returns>
        public abstract ICipherParameters GenerateDerivedParameters(string algorithm, int keySize);
        /// <summary>
        /// Generate derived parameters for a key of the given size (and, where given, an initialization vector).
        /// </summary>
        /// <param name="algorithm">The name of the algorithm the key is for.</param>
        /// <param name="keySize">The size of the key, in bits.</param>
        /// <param name="ivSize">The size of the initialization vector, in bits.</param>
        /// <returns>The derived parameters.</returns>
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
        /// <summary>
        /// Convert a password to bytes according to the PKCS#5 scheme (one byte per character, no padding).
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>The password as bytes.</returns>
        public static byte[] Pkcs5PasswordToBytes(ReadOnlySpan<char> password) => Strings.ToByteArray(password);

        /// <summary>Convert a password to bytes according to the PKCS#5 scheme using UTF-8.</summary>
        /// <param name="password">The password.</param>
        /// <returns>The password as UTF-8 bytes.</returns>
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

        /// <summary>
        /// Convert a password to bytes according to the PKCS#12 scheme (big-endian Unicode with two zero bytes of
        /// padding at the end).
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="wrongPkcs12Zero">
        /// true to produce two zero bytes for an empty password, as some historical implementations did.
        /// </param>
        /// <returns>The password as bytes.</returns>
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
        /// <summary>
        /// Convert a password to bytes according to the PKCS#12 scheme (big-endian Unicode with two zero bytes of
        /// padding at the end).
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>The password as bytes.</returns>
        public static byte[] Pkcs12PasswordToBytes(ReadOnlySpan<char> password) =>
            Pkcs12PasswordToBytes(password, wrongPkcs12Zero: false);

        /// <summary>
        /// Convert a password to bytes according to the PKCS#12 scheme (big-endian Unicode with two zero bytes of
        /// padding at the end).
        /// </summary>
        /// <param name="password">The password.</param>
        /// <param name="wrongPkcs12Zero">
        /// true to produce two zero bytes for an empty password, as some historical implementations did.
        /// </param>
        /// <returns>The password as bytes.</returns>
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
