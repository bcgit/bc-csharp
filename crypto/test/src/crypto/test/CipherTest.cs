using System;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
	public abstract class CipherTest
		: SimpleTest
	{
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
    }
}
