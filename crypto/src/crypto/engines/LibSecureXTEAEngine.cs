using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /**
	* An XTEA engine.
	*/
    public class LibSecureXteaEngine
        : IBlockCipher
    {
        private const int
            rounds = 16,
            block_size = 8;
//			key_size	= 16,

        /*
		* the expanded key array of 4 subkeys
		*/
        private uint[] _S = new uint[4],
            _sum0 = new uint[rounds],
            _sum1 = new uint[rounds],
            _pass1sum0 = new uint[rounds],
            _pass1sum1 = new uint[rounds],
            _pass2sum0 = new uint[rounds],
            _pass2sum1 = new uint[rounds],
            _pass3sum0 = new uint[rounds],
            _pass3sum1 = new uint[rounds],
            _pass4sum0 = new uint[rounds],
            _pass4sum1 = new uint[rounds],
            _pass5sum0 = new uint[rounds],
            _pass5sum1 = new uint[rounds],
            _pass6sum0 = new uint[rounds],
            _pass6sum1 = new uint[rounds],
            _pass7sum0 = new uint[rounds],
            _pass7sum1 = new uint[rounds],
            _pass8sum0 = new uint[rounds],
            _pass8sum1 = new uint[rounds];
        int[] SubSum = new int[rounds + 1]; // Create an array to store data for each round
        private bool _initialised, _forEncryption;

        /**
		* Create an instance of the TEA encryption algorithm
		* and set some defaults
		*/
        public LibSecureXteaEngine()
        {
            _initialised = false;
        }

        public virtual string AlgorithmName
        {
            get { return "LIBSECUREXTEA"; }
        }

        public virtual int GetBlockSize()
        {
            return block_size;
        }

        /**
		* initialise
		*
		* @param forEncryption whether or not we are for encryption.
		* @param params the parameters required to set up the cipher.
		* @exception ArgumentException if the params argument is
		* inappropriate.
		*/
        public virtual void Init(
            bool forEncryption,
            ICipherParameters parameters)
        {
            if (!(parameters is KeyParameter))
            {
                throw new ArgumentException("invalid parameter passed to TEA init - "
                    + Platform.GetTypeName(parameters));
            }

            _forEncryption = forEncryption;
            _initialised = true;

            KeyParameter p = (KeyParameter)parameters;

            setKey(p.GetKey());
        }

        public virtual int ProcessBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff)
        {
            if (!_initialised)
                throw new InvalidOperationException(AlgorithmName + " not initialised");

            Check.DataLength(inBytes, inOff, block_size, "input buffer too short");
            Check.OutputLength(outBytes, outOff, block_size, "output buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return _forEncryption
                ? EncryptBlock(inBytes.AsSpan(inOff), outBytes.AsSpan(outOff))
                : DecryptBlock(inBytes.AsSpan(inOff), outBytes.AsSpan(outOff));
#else
			return _forEncryption
				? EncryptBlock(inBytes, inOff, outBytes, outOff)
				: DecryptBlock(inBytes, inOff, outBytes, outOff);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (!_initialised)
                throw new InvalidOperationException(AlgorithmName + " not initialised");

            Check.DataLength(input, block_size, "input buffer too short");
            Check.OutputLength(output, block_size, "output buffer too short");

            return _forEncryption
                ? EncryptBlock(input, output)
                : DecryptBlock(input, output);
        }
#endif

        /**
		* Re-key the cipher.
		*
		* @param  key  the key to be used
		*/
        private void setKey(
            byte[] key)
        {
            int i, j;
            for (i = j = 0; i < 4; i++, j += 4)
            {
                _S[i] = Pack.BE_To_UInt32(key, j);
            }

            int sum = 0;

            for (i = 0; i < (rounds & 7); i++)
            {
                _sum0[i] = ((uint)sum + _S[sum & 3]);
                sum = sum + unchecked((int)0x9E3779B9);
                _sum1[i] = ((uint)sum + _S[sum >> 11 & 3]);
            }

            for (i = 8; i <= rounds; i = i * 2)
            {
                SubSum[i] = sum;
                sum = ProcessSubKeys(sum, i, true);
            }
        }

        /**
       * Process Per-Block Keys.
       *
       * Libsecure does this, where each block is custom XTEA.
       */
        private int ProcessSubKeys(int sum, int index, bool lookup)
        {
            if (!lookup)
            {
                for (int i = 0; i < ((rounds & index) >> 3); i++)
                {
                    _pass1sum0[i] = ((uint)sum + _S[sum & 3]);
                    int blocksum = sum + unchecked((int)0x9E3779B9);
                    _pass1sum1[i] = ((uint)blocksum + _S[blocksum >> 11 & 3]);
                    _pass2sum0[i] = ((uint)blocksum + _S[blocksum & 3]);
                    blocksum = sum + unchecked((int)0x3C6EF372);
                    _pass2sum1[i] = ((uint)blocksum + _S[blocksum >> 11 & 3]);
                    _pass3sum0[i] = ((uint)blocksum + _S[blocksum & 3]);
                    blocksum = sum + unchecked((int)0xDAA66D2B);
                    _pass3sum1[i] = ((uint)blocksum + _S[blocksum >> 11 & 3]);
                    _pass4sum0[i] = ((uint)blocksum + _S[blocksum & 3]);
                    blocksum = sum + unchecked((int)0x78DDE6E4);
                    _pass4sum1[i] = ((uint)blocksum + _S[blocksum >> 11 & 3]);
                    _pass5sum0[i] = ((uint)blocksum + _S[blocksum & 3]);
                    blocksum = sum + unchecked((int)0x1715609D);
                    _pass5sum1[i] = ((uint)blocksum + _S[blocksum >> 11 & 3]);
                    _pass6sum0[i] = ((uint)blocksum + _S[blocksum & 3]);
                    blocksum = sum + unchecked((int)0xB54CDA56);
                    _pass6sum1[i] = ((uint)blocksum + _S[blocksum >> 11 & 3]);
                    _pass7sum0[i] = ((uint)blocksum + _S[blocksum & 3]);
                    blocksum = sum + unchecked((int)0x5384540F);
                    _pass7sum1[i] = ((uint)blocksum + _S[blocksum >> 11 & 3]);
                    _pass8sum0[i] = ((uint)blocksum + _S[blocksum & 3]);
                    sum = sum + unchecked((int)0xF1BBCDC8);
                    _pass8sum1[i] = ((uint)sum + _S[sum >> 11 & 3]);
                }
            }
            else
            {
                for (int i = 0; i < ((rounds & index) >> 3); i++)
                {
                    sum = sum + unchecked((int)0xF1BBCDC8);
                }
            }

            return sum;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private int EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            // Pack bytes into integers
            uint v0 = Pack.BE_To_UInt32(input);
            uint v1 = Pack.BE_To_UInt32(input[4..]);

            for (int i = 0; i < (rounds & 7); i++)
            {
                v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _sum0[i];
                v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _sum1[i];
            }

            for (int i = 8; i <= rounds; i = i * 2)
            {
                ProcessSubKeys(SubSum[i], i, false);

                for (int j = 0; j < ((rounds & i) >> 3); j++)
                {
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass1sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass1sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass2sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass2sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass3sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass3sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass4sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass4sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass5sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass5sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass6sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass6sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass7sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass7sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass8sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass8sum1[j];
                }
            }

            Pack.UInt32_To_BE(v0, output);
            Pack.UInt32_To_BE(v1, output[4..]);

            return block_size;
        }

        private int DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            // Pack bytes into integers
            uint v0 = Pack.BE_To_UInt32(input);
            uint v1 = Pack.BE_To_UInt32(input[4..]);

            int i = rounds;

            while (i >= 8)
            {
                ProcessSubKeys(SubSum[i], i, false);

                for (int j = ((rounds & i) >> 3) - 1; j >= 0; j--)
                {
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass8sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass8sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass7sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass7sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass6sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass6sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass5sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass5sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass4sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass4sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass3sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass3sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass2sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass2sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass1sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass1sum0[j];
                }

                i = i / 2;
            }

            for (i = (rounds & 7) - 1; i >= 0; i--)
            {
                v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _sum1[i];
                v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _sum0[i];
            }

            Pack.UInt32_To_BE(v0, output);
            Pack.UInt32_To_BE(v1, output[4..]);

            return block_size;
        }
#else
		private int EncryptBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff)
		{
			uint v0 = Pack.BE_To_UInt32(inBytes, inOff);
			uint v1 = Pack.BE_To_UInt32(inBytes, inOff + 4);

			for (int i = 0; i < (rounds & 7); i++)
            {
                v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _sum0[i];
                v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _sum1[i];
            }

            for (int i = 8; i <= rounds; i = i * 2)
            {
                ProcessSubKeys(SubSum[i], i, false);

                for (int j = 0; j < ((rounds & i) >> 3); j++)
                {
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass1sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass1sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass2sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass2sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass3sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass3sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass4sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass4sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass5sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass5sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass6sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass6sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass7sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass7sum1[j];
                    v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass8sum0[j];
                    v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass8sum1[j];
                }
            }

			Pack.UInt32_To_BE(v0, outBytes, outOff);
			Pack.UInt32_To_BE(v1, outBytes, outOff + 4);

			return block_size;
		}

		private int DecryptBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff)
		{
			// Pack bytes into integers
			uint v0 = Pack.BE_To_UInt32(inBytes, inOff);
			uint v1 = Pack.BE_To_UInt32(inBytes, inOff + 4);

			int i = rounds;

            while (i >= 8)
            {
                ProcessSubKeys(SubSum[i], i, false);

                for (int j = ((rounds & i) >> 3) - 1; j >= 0; j--)
                {
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass8sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass8sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass7sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass7sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass6sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass6sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass5sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass5sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass4sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass4sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass3sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass3sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass2sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass2sum0[j];
                    v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _pass1sum1[j];
                    v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _pass1sum0[j];
                }

                i = i / 2;
            }

            for (i = (rounds & 7) - 1; i >= 0; i--)
            {
                v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ _sum1[i];
                v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ _sum0[i];
            }

			Pack.UInt32_To_BE(v0, outBytes, outOff);
			Pack.UInt32_To_BE(v1, outBytes, outOff + 4);

			return block_size;
		}
#endif
    }
}