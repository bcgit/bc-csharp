using System;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    public abstract class CipherTest
		: SimpleTest
	{
        internal delegate IAeadCipher CreateAeadCipher();
        internal delegate IBlockCipher CreateBlockCipher();

        private readonly SimpleTest[] m_tests;
		private readonly IBlockCipher m_engine;
		private readonly KeyParameter m_validKey;

		protected CipherTest()
		{
            m_tests = null;
            m_engine = null;
            m_validKey = null;
        }

        protected CipherTest(SimpleTest[] tests, IBlockCipher engine, KeyParameter validKey)
		{
            m_tests = tests;
			m_engine = engine;
			m_validKey = validKey;
		}

		public override void PerformTest()
		{
			if (m_tests != null)
			{
                RunTests(m_tests);
            }

            if (m_engine != null)
			{
                RunEngineChecks(m_engine, m_validKey);
            }
		}

        protected void RunEngineChecks(IBlockCipher engine, KeyParameter validKey)
        {
            byte[] buf = new byte[engine.GetBlockSize()];
            ExpectInvalidOperationException(engine, buf, buf, "failed initialisation check");

            CheckDataLengthExceptions(engine, validKey);
        }

        protected void RunTests(SimpleTest[] tests)
        {
            foreach (var test in tests)
            {
                test.PerformTest();
            }
        }

        private void CheckDataLengthExceptions(IBlockCipher engine, ICipherParameters parameters)
		{
			byte[] correctBuf = new byte[engine.GetBlockSize()];
			byte[] shortBuf = new byte[correctBuf.Length / 2];

            engine.Init(true, parameters);

			ExpectDataLengthException(engine, shortBuf, correctBuf, "failed short input check");
            ExpectDataLengthException(engine, correctBuf, shortBuf, "failed short output check");

			engine.Init(false, parameters);

            ExpectDataLengthException(engine, shortBuf, correctBuf, "failed short input check");
            ExpectDataLengthException(engine, correctBuf, shortBuf, "failed short output check");
		}

        private void ExpectDataLengthException(IBlockCipher engine, byte[] input, byte[] output, string message)
		{
            try
            {
                engine.ProcessBlock(input, 0, output, 0);
                Fail(message);
            }
            catch (DataLengthException)
            {
                // expected
            }
        }

        private void ExpectInvalidOperationException(IBlockCipher engine, byte[] input, byte[] output, string message)
        {
            try
            {
                engine.ProcessBlock(input, 0, output, 0);
                Fail(message);
            }
            catch (InvalidOperationException)
            {
                // expected
            }
        }

        internal static bool TestAeadCipher(int aeadLen, int ivLen, int msgLen, int strength, CreateAeadCipher create)
        {
            IAeadCipher pCipher = create();
            /* Obtain some random data */
            byte[] myData = new byte[msgLen];
            SecureRandom myRandom = new SecureRandom();
            myRandom.NextBytes(myData);
            /* Obtain some random Aead */
            byte[] myAEAD = new byte[aeadLen];
            myRandom.NextBytes(myAEAD);
            /* Create the Key parameters */
            CipherKeyGenerator myGenerator = new CipherKeyGenerator();
            KeyGenerationParameters myGenParams = new KeyGenerationParameters(myRandom, strength);
            myGenerator.Init(myGenParams);
            byte[] myKey = myGenerator.GenerateKey();
            KeyParameter myKeyParams = new KeyParameter(myKey);
            /* Create the nonce */
            byte[] myNonce = new byte[ivLen];
            myRandom.NextBytes(myNonce);
            ParametersWithIV myParams = new ParametersWithIV(myKeyParams, myNonce);
            /* Initialise the cipher for encryption */
            pCipher.Init(true, myParams);
            int myMaxOutLen = pCipher.GetOutputSize(msgLen);
            byte[] myEncrypted = new byte[myMaxOutLen];
            pCipher.ProcessAadBytes(myAEAD, 0, aeadLen);
            int myOutLen = pCipher.ProcessBytes(myData, 0, msgLen, myEncrypted, 0);
            myOutLen += pCipher.DoFinal(myEncrypted, myOutLen);
            /* Note that myOutLen is too large by Datalen */
            pCipher = create();
            /* Initialise the cipher for decryption */
            pCipher.Init(false, myParams);
            int myMaxClearLen = pCipher.GetOutputSize(myOutLen);
            byte[] myDecrypted = new byte[myMaxClearLen];
            pCipher.ProcessAadBytes(myAEAD, 0, aeadLen);
            int myClearLen = pCipher.ProcessBytes(myEncrypted, 0, myEncrypted.Length, myDecrypted, 0);
            myClearLen += pCipher.DoFinal(myDecrypted, myClearLen);
            byte[] myResult = Arrays.CopyOf(myDecrypted, msgLen);
            /* Check that we have the same result */
            return Arrays.AreEqual(myData, myResult);
        }
    }
}
