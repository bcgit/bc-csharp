using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Text;

namespace crypto
{
    public class Security
    {
        // USAGE

        //var key = Security.GenerateText(32);

        //var iv = Security.GenerateText(16);

        //var encrypted = Security.Encrypt("MY SECRET", key, iv);

        //var dencrypted = Security.Decrypt(encrypted, key, iv);


        /// <summary>
        /// Return a salted hash based on PBKDF2 for the UTF-8 encoding of the argument text.
        /// </summary>
        /// <param name="text">Provided key text</param>
        /// <param name="salt">Base64 encoded string representing the salt</param>
        /// <returns></returns>
        public static String ComputeHash(string text, string salt)
        {
            var data = Encoding.UTF8.GetBytes(text);
            var sha = new Sha512Digest();
            var gen = new Pkcs5S2ParametersGenerator(sha);

            gen.Init(data, Convert.FromBase64String(salt), 2048);

            return Convert.ToBase64String(((KeyParameter)gen.GenerateDerivedParameters(sha.GetDigestSize() * 8)).GetKey());
        }

        public static String Decrypt(String cipherText, String key, String iv)

        {

            var cipher = CreateCipher(false, key, iv);

            var textAsBytes = cipher.DoFinal(Convert.FromBase64String(cipherText));



            return Encoding.UTF8.GetString(textAsBytes, 0, textAsBytes.Length);

        }



        public static String Encrypt(String plainText, String key, String iv)

        {

            var cipher = CreateCipher(true, key, iv);



            return Convert.ToBase64String(cipher.DoFinal(Encoding.UTF8.GetBytes(plainText)));

        }



        public static String GenerateText(int size)

        {

            var textAsBytes = new Byte[size];

            var secureRandom = SecureRandom.GetInstance("SHA256PRNG", true);



            secureRandom.NextBytes(textAsBytes);

            return Convert.ToBase64String(textAsBytes);

        }



        private static PaddedBufferedBlockCipher CreateCipher(Boolean isEncryption, String key, String iv)

        {

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new RijndaelEngine()), new ISO10126d2Padding());

            var keyParam = new KeyParameter(Convert.FromBase64String(key));

            ICipherParameters cipherParams = String.IsNullOrEmpty(iv) ? (ICipherParameters)keyParam : new ParametersWithIV(keyParam, Convert.FromBase64String(iv));

            cipher.Init(isEncryption, cipherParams);

            return cipher;

        }
    }
}
