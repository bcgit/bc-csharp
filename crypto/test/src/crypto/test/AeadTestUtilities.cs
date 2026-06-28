using System;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
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
            catch (InvalidCipherTextException)
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
            catch (InvalidCipherTextException)
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

        public static void TestReset(ITest test, IAeadCipher cipher1, IAeadBlockCipher cipher2, ICipherParameters cipherParameters)
        {
            cipher1.Init(true, cipherParameters);

            byte[] plaintext = new byte[1000];
            byte[] ciphertext = new byte[cipher1.GetOutputSize(plaintext.Length)];

            // Establish baseline answer
            Crypt(cipher1, plaintext, ciphertext);

            // Test encryption resets
            CheckReset(test, cipher1, cipherParameters, true, plaintext, ciphertext);

            // Test decryption resets with fresh instance
            cipher2.Init(false, cipherParameters);
            CheckReset(test, cipher2, cipherParameters, false, ciphertext, plaintext);
        }

        private static void CheckReset(ITest test, IAeadCipher cipher, ICipherParameters cipherParameters, bool encrypt,
            byte[] pretext, byte[] posttext)
        {
            // Do initial run
            byte[] output = new byte[posttext.Length];
            Crypt(cipher, pretext, output);

            // Check encrypt resets cipher
            Crypt(cipher, pretext, output);
            if (!Arrays.AreEqual(output, posttext))
            {
                Fail(test, (encrypt? "Encrypt" : "Decrypt") + " did not reset cipher.");
            }

            // Check init resets data
            cipher.ProcessBytes(pretext, 0, 100, output, 0);
            ResetForCheck(cipher, cipherParameters, encrypt);

            try
            {
                Crypt(cipher, pretext, output);
            }
            catch (DataLengthException e)
            {
                Fail(test, "Init did not reset data.");
            }
            if (!Arrays.AreEqual(output, posttext))
            {
                Fail(test, "Init did not reset data.", Hex.ToHexString(posttext), Hex.ToHexString(output));
            }

            // Check init resets AD
            cipher.ProcessAadBytes(pretext, 0, 100);
            ResetForCheck(cipher, cipherParameters, encrypt);

            try
            {
                Crypt(cipher, pretext, output);
            }
            catch (DataLengthException e)
            {
                Fail(test, "Init did not reset additional data.");
            }
            if (!Arrays.AreEqual(output, posttext))
            {
                Fail(test, "Init did not reset additional data.");
            }

            // Check reset resets data
            cipher.ProcessBytes(pretext, 0, 100, output, 0);
            cipher.Reset();

            try
            {
                Crypt(cipher, pretext, output);
            }
            catch (DataLengthException e)
            {
                Fail(test, "Init did not reset data.");
            }
            if (!Arrays.AreEqual(output, posttext))
            {
                Fail(test, "Reset did not reset data.");
            }

            // Check reset resets AD
            cipher.ProcessAadBytes(pretext, 0, 100);
            cipher.Reset();

            try
            {
                Crypt(cipher, pretext, output);
            }
            catch (DataLengthException e)
            {
                Fail(test, "Init did not reset data.");
            }
            if (!Arrays.AreEqual(output, posttext))
            {
                Fail(test, "Reset did not reset additional data.");
            }
        }

        private static void ResetForCheck(IAeadCipher cipher, ICipherParameters cipherParameters, bool encrypt)
        {
            // Re-initialising for encryption with the same key+nonce is rejected by the nonce-reuse
            // guard (GCM-family modes), so exercise reset() on the encrypt path; the decrypt path keeps
            // verifying that init() clears buffered data/AAD.
            if (encrypt)
            {
                cipher.Reset();
            }
            else
            {
                cipher.Init(false, cipherParameters);
            }
        }

        private static void Crypt(IAeadCipher cipher, byte[] plaintext, byte[] output)
        {
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            cipher.DoFinal(output, len);
        }

        private static AeadParameters VaryNonce(AeadParameters aeadParameters, int counter)
        {
            // Perturb the nonce so successive encryption re-inits never repeat one: the GCM-family
            // nonce-reuse guard rejects a repeated key+nonce on init for encryption, and these
            // size/buffer helpers do not depend on the nonce value (only on lengths and reset state).
            // A non-zero counter guarantees the result differs from the supplied nonce.
            byte[] nonce = Arrays.Clone(aeadParameters.GetNonce());
            for (int i = 0; i < nonce.Length && i < 4; i++)
            {
                nonce[i] ^= (byte)(((uint)counter >> (8 * i)));
            }
            return new AeadParameters(aeadParameters.Key, aeadParameters.MacSize, nonce, aeadParameters.GetAssociatedText());
        }

        public static void TestOutputSizes(ITest test, IAeadBlockCipher cipher, AeadParameters aeadParameters)
        {
            int maxPlaintext = cipher.UnderlyingCipher.GetBlockSize() * 10;
            byte[] plaintext = new byte[maxPlaintext];
            byte[] ciphertext = new byte[maxPlaintext * 2];

            // Check output size calculations for truncated ciphertext lengths
            cipher.Init(true, aeadParameters);
            cipher.DoFinal(ciphertext, 0);
            int macLength = cipher.GetMac().Length;

            cipher.Init(false, aeadParameters);
            for (int i = 0; i < macLength; i++)
            {
                cipher.Reset();
                if (cipher.GetUpdateOutputSize(i) != 0)
                {
                    Fail(test, "AE cipher should not produce update output with ciphertext length <= macSize");
                }
                if (cipher.GetOutputSize(i) != 0)
                {
                    Fail(test, "AE cipher should not produce output with ciphertext length <= macSize");
                }
            }

            for (int i = 0; i < plaintext.Length; i++)
            {
                AeadParameters paramsI = VaryNonce(aeadParameters, i + 1);
                cipher.Init(true, paramsI);
                int expectedCTUpdateSize = cipher.GetUpdateOutputSize(i);
                int expectedCTOutputSize = cipher.GetOutputSize(i);

                if (expectedCTUpdateSize < 0)
                {
                    Fail(test, "Encryption update output size should not be < 0 for size " + i);
                }

                if (expectedCTOutputSize < 0)
                {
                    Fail(test, "Encryption update output size should not be < 0 for size " + i);
                }

                int actualCTSize = cipher.ProcessBytes(plaintext, 0, i, ciphertext, 0);

                if (expectedCTUpdateSize != actualCTSize)
                {
                    Fail(test, "Encryption update output size did not match calculated for plaintext length " + i,
                        expectedCTUpdateSize.ToString(), actualCTSize.ToString());
                }

                actualCTSize += cipher.DoFinal(ciphertext, actualCTSize);

                if (expectedCTOutputSize != actualCTSize)
                {
                    Fail(test, "Encryption actual final output size did not match calculated for plaintext length " + i,
                        expectedCTOutputSize.ToString(), actualCTSize.ToString());
                }

                cipher.Init(false, paramsI);
                int expectedPTUpdateSize = cipher.GetUpdateOutputSize(actualCTSize);
                int expectedPTOutputSize = cipher.GetOutputSize(actualCTSize);

                if (expectedPTOutputSize != i)
                {
                    Fail(test, "Decryption update output size did not original plaintext length " + i,
                        expectedPTUpdateSize.ToString(), i.ToString());
                }

                int actualPTSize = cipher.ProcessBytes(ciphertext, 0, actualCTSize, plaintext, 0);

                if (expectedPTUpdateSize != actualPTSize)
                {
                    Fail(test, "Decryption update output size did not match calculated for plaintext length " + i,
                        expectedPTUpdateSize.ToString(), actualPTSize.ToString());
                }

                actualPTSize += cipher.DoFinal(plaintext, actualPTSize);

                if (expectedPTOutputSize != actualPTSize)
                {
                    Fail(test, "Decryption update output size did not match calculated for plaintext length " + i,
                        expectedPTOutputSize.ToString(), actualPTSize.ToString());
                }
            }
        }

        public static void TestBufferSizeChecks(ITest test, IAeadBlockCipher cipher, AeadParameters aeadParameters)
        {
            int blockSize = cipher.UnderlyingCipher.GetBlockSize();
            int maxPlaintext = blockSize * 10;
            byte[] plaintext = new byte[maxPlaintext];

            cipher.Init(true, aeadParameters);

            int expectedUpdateOutputSize = cipher.GetUpdateOutputSize(plaintext.Length);
            byte[] ciphertext = new byte[cipher.GetOutputSize(plaintext.Length)];

            try
            {
                cipher.ProcessBytes(new byte[maxPlaintext - 1], 0, maxPlaintext, new byte[expectedUpdateOutputSize], 0);
                Fail(test, "ProcessBytes should validate input buffer length");
            }
            catch (DataLengthException e)
            {
                // Expected
            }
            cipher.Reset();

            if (expectedUpdateOutputSize > 0)
            {
                int outputTrigger = 0;
                // Process bytes until output would be produced
                for (int i = 0; i < plaintext.Length; i++)
                {
                    if (cipher.GetUpdateOutputSize(1) != 0)
                    {
                        outputTrigger = i + 1;
                        break;
                    }
                    cipher.ProcessByte(plaintext[i], ciphertext, 0);
                }
                if (outputTrigger == 0)
                {
                    Fail(test, "Failed to find output trigger size");
                }
                try
                {
                    cipher.ProcessByte(plaintext[0], new byte[cipher.GetUpdateOutputSize(1) - 1], 0);
                    Fail(test, "Encrypt ProcessByte should validate output buffer length");
                }
                catch (OutputLengthException e)
                {
                    // Expected
                }
                cipher.Reset();

                // Repeat checking with entire input at once
                try
                {
                    cipher.ProcessBytes(plaintext, 0, outputTrigger,
                        new byte[cipher.GetUpdateOutputSize(outputTrigger) - 1], 0);
                    Fail(test, "Encrypt ProcessBytes should validate output buffer length");
                }
                catch (OutputLengthException e)
                {
                    // Expected
                }
                cipher.Reset();
            }

            // Remember the actual ciphertext for later
            int actualOutputSize = cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
            actualOutputSize += cipher.DoFinal(ciphertext, actualOutputSize);
            int macSize = cipher.GetMac().Length;

            cipher.Reset();
            try
            {
                cipher.ProcessBytes(plaintext, 0, plaintext.Length, ciphertext, 0);
                cipher.DoFinal(new byte[cipher.GetOutputSize(0) - 1], 0);
                Fail(test, "Encrypt DoFinal should validate output buffer length");
            }
            catch (OutputLengthException e)
            {
                // Expected
            }

            // Decryption tests

            cipher.Init(false, aeadParameters);
            expectedUpdateOutputSize = cipher.GetUpdateOutputSize(actualOutputSize);

            if (expectedUpdateOutputSize > 0)
            {
                // Process bytes until output would be produced
                int outputTrigger = 0;
                for (int i = 0; i < plaintext.Length; i++)
                {
                    if (cipher.GetUpdateOutputSize(1) != 0)
                    {
                        outputTrigger = i + 1;
                        break;
                    }
                    cipher.ProcessByte(ciphertext[i], plaintext, 0);
                }
                if (outputTrigger == 0)
                {
                    Fail(test, "Failed to find output trigger size");
                }

                try
                {
                    cipher.ProcessByte(ciphertext[0], new byte[cipher.GetUpdateOutputSize(1) - 1], 0);
                    Fail(test, "Decrypt ProcessByte should validate output buffer length");
                }
                catch (OutputLengthException e)
                {
                    // Expected
                }
                cipher.Reset();

                // Repeat test with ProcessBytes
                try
                {
                    cipher.ProcessBytes(ciphertext, 0, outputTrigger,
                        new byte[cipher.GetUpdateOutputSize(outputTrigger) - 1], 0);
                    Fail(test, "Decrypt ProcessBytes should validate output buffer length");
                }
                catch (OutputLengthException)
                {
                    // Expected
                }
            }

            cipher.Reset();
            // Data less than mac length should fail before output length check
            try
            {
                // Assumes AE cipher on decrypt can't return any data until macSize bytes are received
                if (cipher.ProcessBytes(ciphertext, 0, macSize - 1, plaintext, 0) != 0)
                {
                    Fail(test, "AE cipher unexpectedly produced output");
                }
                cipher.DoFinal(new byte[0], 0);
                Fail(test, "Decrypt DoFinal should check ciphertext length");
            }
            catch (InvalidCipherTextException)
            {
                // Expected
            }

            try
            {
                // Search through plaintext lengths until one is found that creates >= 1 buffered byte
                // during decryption of ciphertext for DoFinal to handle
                for (int i = 2; i < plaintext.Length; i++)
                {
                    AeadParameters paramsI = VaryNonce(aeadParameters, i);
                    cipher.Init(true, paramsI);
                    int encrypted = cipher.ProcessBytes(plaintext, 0, i, ciphertext, 0);
                    encrypted += cipher.DoFinal(ciphertext, encrypted);

                    cipher.Init(false, paramsI);
                    cipher.ProcessBytes(ciphertext, 0, encrypted - 1, plaintext, 0);
                    if (cipher.ProcessByte(ciphertext[encrypted - 1], plaintext, 0) == 0)
                    {
                        cipher.DoFinal(new byte[cipher.GetOutputSize(0) - 1], 0);
                        Fail(test, "Decrypt DoFinal should check output length");
                        cipher.Reset();

                        // Truncated Mac should be reported in preference to inability to output
                        // buffered plaintext byte
                        try
                        {
                            cipher.ProcessBytes(ciphertext, 0, actualOutputSize - 1, plaintext, 0);
                            cipher.DoFinal(new byte[cipher.GetOutputSize(0) - 1], 0);
                            Fail(test, "Decrypt DoFinal should check ciphertext length");
                        }
                        catch (InvalidCipherTextException e)
                        {
                            // Expected
                        }
                        cipher.Reset();
                    }
                }
                Fail(test, "Decrypt DoFinal test couldn't find a ciphertext length that buffered for DoFinal");
            }
            catch (OutputLengthException)
            {
                // Expected
            }
        }

        internal static AeadParameters ReuseKey(AeadParameters p) =>
            new AeadParameters(null, p.MacSize, p.GetNonce(), p.GetAssociatedText());
    }
}
