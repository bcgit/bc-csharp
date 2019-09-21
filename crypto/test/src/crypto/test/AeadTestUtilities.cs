using System;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    public class AeadTestUtilities
    {
        internal static void TestTampering(ITest test, IAeadCipher cipher, ICipherParameters parameters)
        {
            byte[] plaintext = new byte[1000];
            for (int i = 0; i < plaintext.Length; i++)
            {
                plaintext[i] = (byte)i;
            }
            cipher.Init(true, parameters);

            byte[] ciphertext = new byte[cipher.GetOutputSize(plaintext.Length)];
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
            cipher.DoFinal(ciphertext, len);

            int macLength = cipher.GetMac().Length;

            // Test tampering with a single byte
            cipher.Init(false, parameters);
            byte[] tampered = new byte[ciphertext.Length];
            byte[] output = new byte[plaintext.Length];
            Array.Copy(ciphertext, 0, tampered, 0, tampered.Length);
            tampered[0] += 1;

            cipher.ProcessBytes(tampered, 0, tampered.Length, output, 0);
            try
            {
                cipher.DoFinal(output, 0);
                throw new TestFailedException(
                    new SimpleTestResult(false, test + " : tampering of ciphertext not detected."));
            }
            catch (InvalidCipherTextException e)
            {
                // Expected
            }

            // Test truncation of ciphertext to < tag length
            cipher.Init(false, parameters);
            byte[] truncated = new byte[macLength - 1];
            Array.Copy(ciphertext, 0, truncated, 0, truncated.Length);

            cipher.ProcessBytes(truncated, 0, truncated.Length, output, 0);
            try
            {
                cipher.DoFinal(output, 0);
                Fail(test, "tampering of ciphertext not detected.");
            }
            catch (InvalidCipherTextException e)
            {
                // Expected
            }
        }

        private static void Fail(ITest test, string message)
        {
            throw new TestFailedException(SimpleTestResult.Failed(test, message));
        }

        private static void Fail(ITest test, string message, string expected, string result)
        {
            throw new TestFailedException(SimpleTestResult.Failed(test, message, expected, result));
        }

        internal static AeadParameters ReuseKey(AeadParameters p)
        {
            return new AeadParameters(null, p.MacSize, p.GetNonce(), p.GetAssociatedText());
        }
    }
}
