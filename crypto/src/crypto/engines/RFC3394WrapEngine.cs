using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>An implementation of the AES Key Wrap with Padding specification as described in RFC 3349.</summary>
    /// <remarks>
    /// For further details see: Schaad, J. and R. Housley, "Advanced Encryption Standard (AES) Key Wrap Algorithm",
    /// RFC 3394, DOI 10.17487/RFC3394, September 2002, <https://www.rfc-editor.org/info/rfc3394>, and
    /// http://csrc.nist.gov/encryption/kms/key-wrap.pdf.
    /// </remarks>
    public class Rfc3394WrapEngine
		: IWrapper
	{
        private static readonly byte[] DefaultIV = { 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6 };

        private readonly IBlockCipher m_engine;
        private readonly bool m_wrapCipherMode;
        private readonly byte[] m_iv = new byte[8];

        private KeyParameter m_key = null;
		private bool m_forWrapping = true;

		public Rfc3394WrapEngine(IBlockCipher engine)
			: this(engine, false)
		{
		}

        public Rfc3394WrapEngine(IBlockCipher engine, bool useReverseDirection)
        {
            m_engine = engine;
            m_wrapCipherMode = !useReverseDirection;
        }

		public virtual string AlgorithmName => m_engine.AlgorithmName;

        public virtual void Init(bool forWrapping, ICipherParameters parameters)
		{
			m_forWrapping = forWrapping;

			if (parameters is ParametersWithRandom withRandom)
			{
				parameters = withRandom.Parameters;
			}

			if (parameters is KeyParameter keyParameter)
			{
				m_key = keyParameter;
                Array.Copy(DefaultIV, 0, m_iv, 0, 8);
            }
            else if (parameters is ParametersWithIV withIV)
			{
				byte[] iv = withIV.GetIV();
				if (iv.Length != 8)
					throw new ArgumentException("IV length not equal to 8", nameof(parameters));

                m_key = (KeyParameter)withIV.Parameters;
                Array.Copy(iv, 0, m_iv, 0, 8);
			}
			else
			{
				// TODO Throw an exception for bad parameters?
			}
		}

        public virtual byte[] Wrap(byte[] input, int inOff, int inLen)
		{
			if (!m_forWrapping)
				throw new InvalidOperationException("not set for wrapping");
            if (inLen < 8)
                throw new DataLengthException("wrap data must be at least 8 bytes");

            int n = inLen / 8;

			if ((n * 8) != inLen)
				throw new DataLengthException("wrap data must be a multiple of 8 bytes");

            m_engine.Init(m_wrapCipherMode, m_key);

            byte[] block = new byte[inLen + 8];
			Array.Copy(m_iv, 0, block, 0, 8);
			Array.Copy(input, inOff, block, 8, inLen);

			if (n == 1)
			{
                m_engine.ProcessBlock(block, 0, block, 0);
            }
            else
			{
                byte[] buf = new byte[16];

                for (int j = 0; j != 6; j++)
				{
					for (int i = 1; i <= n; i++)
					{
						Array.Copy(block, 0, buf, 0, 8);
						Array.Copy(block, 8 * i, buf, 8, 8);
						m_engine.ProcessBlock(buf, 0, buf, 0);

						uint t = (uint)(n * j + i);
						for (int k = 1; t != 0U; k++)
						{
							buf[8 - k] ^= (byte)t;
							t >>= 8;
						}

						Array.Copy(buf, 0, block, 0, 8);
						Array.Copy(buf, 8, block, 8 * i, 8);
					}
				}
            }

            return block;
		}

        public virtual byte[] Unwrap(byte[] input, int inOff, int inLen)
		{
			if (m_forWrapping)
				throw new InvalidOperationException("not set for unwrapping");
            if (inLen < 16)
                throw new InvalidCipherTextException("unwrap data too short");

			int n = inLen / 8;

			if ((n * 8) != inLen)
				throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");

            m_engine.Init(!m_wrapCipherMode, m_key);

            byte[] block = new byte[inLen - 8];
			byte[] a = new byte[8];
			byte[] buf = new byte[16];

			n = n - 1;

			if (n == 1)
			{
                m_engine.ProcessBlock(input, inOff, buf, 0);
                Array.Copy(buf, 0, a, 0, 8);
                Array.Copy(buf, 8, block, 0, 8);
            }
            else
			{
                Array.Copy(input, inOff, a, 0, 8);
                Array.Copy(input, inOff + 8, block, 0, inLen - 8);

				for (int j = 5; j >= 0; j--)
				{
					for (int i = n; i >= 1; i--)
					{
						Array.Copy(a, 0, buf, 0, 8);
						Array.Copy(block, 8 * (i - 1), buf, 8, 8);

						uint t = (uint)(n * j + i);
						for (int k = 1; t != 0; k++)
						{
							buf[8 - k] ^= (byte)t;
							t >>= 8;
						}

						m_engine.ProcessBlock(buf, 0, buf, 0);
						Array.Copy(buf, 0, a, 0, 8);
						Array.Copy(buf, 8, block, 8 * (i - 1), 8);
					}
				}
            }

            if (!Arrays.FixedTimeEquals(a, m_iv))
				throw new InvalidCipherTextException("checksum failed");

			return block;
		}
	}
}
