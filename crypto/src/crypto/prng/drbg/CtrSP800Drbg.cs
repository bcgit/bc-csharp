using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Prng.Drbg
{
	/**
	 * A SP800-90A CTR DRBG.
	 */
	public sealed class CtrSP800Drbg
        :   ISP80090Drbg
	{
	    private static readonly long TDEA_RESEED_MAX = 1L << (32 - 1);
		private static readonly long AES_RESEED_MAX = 1L << (48 - 1);
		private static readonly int TDEA_MAX_BITS_REQUEST = 1 << (13 - 1);
		private static readonly int AES_MAX_BITS_REQUEST = 1 << (19 - 1);

        private readonly IEntropySource  mEntropySource;
	    private readonly IBlockCipher    mEngine;
	    private readonly int             mKeySizeInBits;
	    private readonly int             mSeedLength;
	    private readonly int             mSecurityStrength;

        // internal state
	    private byte[]                mKey;
	    private byte[]                mV;
	    private long                  mReseedCounter = 0;
	    private bool                  mIsTdea = false;

	    /**
	     * Construct a SP800-90A CTR DRBG.
	     * <p>
	     * Minimum entropy requirement is the security strength requested.
	     * </p>
	     * @param engine underlying block cipher to use to support DRBG
	     * @param keySizeInBits size of the key to use with the block cipher.
	     * @param securityStrength security strength required (in bits)
	     * @param entropySource source of entropy to use for seeding/reseeding.
	     * @param personalizationString personalization string to distinguish this DRBG (may be null).
	     * @param nonce nonce to further distinguish this DRBG (may be null).
	     */
	    public CtrSP800Drbg(IBlockCipher engine, int keySizeInBits, int securityStrength, IEntropySource entropySource,
            byte[] personalizationString, byte[] nonce)
	    {
	        if (securityStrength > 256)
	            throw new ArgumentException("Requested security strength is not supported by the derivation function");
	        if (GetMaxSecurityStrength(engine, keySizeInBits) < securityStrength)
	            throw new ArgumentException("Requested security strength is not supported by block cipher and key size");
	        if (entropySource.EntropySize < securityStrength)
	            throw new ArgumentException("Not enough entropy for security strength required");

            mEntropySource = entropySource;
	        mEngine = engine;     

            mKeySizeInBits = keySizeInBits;
	        mSecurityStrength = securityStrength;
	        mSeedLength = keySizeInBits + engine.GetBlockSize() * 8;
	        mIsTdea = IsTdea(engine);

            CTR_DRBG_Instantiate_algorithm(nonce, personalizationString);
	    }

        private void CTR_DRBG_Instantiate_algorithm(byte[] nonce, byte[] personalisationString)
	    {
            byte[] entropy = GetEntropy();  // Get_entropy_input
            byte[] seedMaterial = Arrays.ConcatenateAll(entropy, nonce, personalisationString);
	        byte[] seed = BlockCipherDF(seedMaterial, mSeedLength / 8);

            int blockSize = mEngine.GetBlockSize();

            mKey = new byte[(mKeySizeInBits + 7) / 8];
	        mV = new byte[blockSize];

	        // mKey & mV are modified by this call
	        CTR_DRBG_Update(seed, mKey, mV); 

            mReseedCounter = 1;
	    }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void CTR_DRBG_Update(ReadOnlySpan<byte> seed, Span<byte> key, Span<byte> v)
        {
			int seedLength = seed.Length;
            Span<byte> temp = seedLength <= 256
				? stackalloc byte[seedLength]
                : new byte[seedLength];

			int blockSize = mEngine.GetBlockSize();
            Span<byte> block = blockSize <= 64
				? stackalloc byte[blockSize]
                : new byte[blockSize];

			mEngine.Init(true, ExpandToKeyParameter(key));
            for (int i = 0; i * blockSize < seed.Length; ++i)
            {
                AddOneTo(v);
                mEngine.ProcessBlock(v, block);

                int bytesToCopy = System.Math.Min(blockSize, temp.Length - i * blockSize);
				block[..bytesToCopy].CopyTo(temp[(i * blockSize)..]);
            }

			XorWith(seed, temp);

			key.CopyFrom(temp);
			v.CopyFrom(temp[key.Length..]);
        }
#else
        private void CTR_DRBG_Update(byte[] seed, byte[] key, byte[] v)
	    {
			byte[] temp = new byte[seed.Length];
	        byte[] outputBlock = new byte[mEngine.GetBlockSize()];

            int i = 0;
	        int outLen = mEngine.GetBlockSize();

			mEngine.Init(true, ExpandToKeyParameter(key));
	        while (i * outLen < seed.Length)
	        {
	            AddOneTo(v);
	            mEngine.ProcessBlock(v, 0, outputBlock, 0);

				int bytesToCopy = System.Math.Min(outLen, temp.Length - i * outLen);
	            Array.Copy(outputBlock, 0, temp, i * outLen, bytesToCopy);
	            ++i;
	        }

	        Xor(temp, seed, temp, 0);

	        Array.Copy(temp, 0, key, 0, key.Length);
	        Array.Copy(temp, key.Length, v, 0, v.Length);
        }
#endif

        private void CTR_DRBG_Reseed_algorithm(byte[] additionalInput)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
			CTR_DRBG_Reseed_algorithm(Spans.FromNullableReadOnly(additionalInput));
#else
			byte[] seedMaterial = Arrays.Concatenate(GetEntropy(), additionalInput);

            seedMaterial = BlockCipherDF(seedMaterial, mSeedLength / 8);

            CTR_DRBG_Update(seedMaterial, mKey, mV);

            mReseedCounter = 1;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void CTR_DRBG_Reseed_algorithm(ReadOnlySpan<byte> additionalInput)
        {
			int entropyLength = GetEntropyLength();
			int seedLength = entropyLength + additionalInput.Length;

			Span<byte> seedMaterial = seedLength <= 256
				? stackalloc byte[seedLength]
				: new byte[seedLength];

			GetEntropy(seedMaterial[..entropyLength]);
			additionalInput.CopyTo(seedMaterial[entropyLength..]);

            seedMaterial = BlockCipherDF(seedMaterial, mSeedLength / 8);

            CTR_DRBG_Update(seedMaterial, mKey, mV);

            mReseedCounter = 1;
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void Xor(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, Span<byte> z)
        {
            for (int i = 0; i < z.Length; ++i)
            {
                z[i] = (byte)(x[i] ^ y[i]);
            }
        }

        private void XorWith(ReadOnlySpan<byte> x, Span<byte> z)
        {
            for (int i = 0; i < z.Length; ++i)
            {
				z[i] ^= x[i];
            }
        }
#else
        private void Xor(byte[] output, byte[] a, byte[] b, int bOff)
	    {
            for (int i = 0; i < output.Length; i++) 
	        {
                output[i] = (byte)(a[i] ^ b[bOff + i]);
	        }
	    }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void AddOneTo(Span<byte> longer)
#else
		private void AddOneTo(byte[] longer)
#endif
        {
            uint carry = 1;
            int i = longer.Length;
            while (--i >= 0)
            {
                carry += longer[i];
                longer[i] = (byte)carry;
                carry >>= 8;
            }
	    } 

        private byte[] GetEntropy()
	    {
	        byte[] entropy = mEntropySource.GetEntropy();
	        if (entropy.Length < (mSecurityStrength + 7) / 8)
	            throw new InvalidOperationException("Insufficient entropy provided by entropy source");
	        return entropy;
	    }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private int GetEntropy(Span<byte> output)
        {
			int length = mEntropySource.GetEntropy(output);
            if (length < (mSecurityStrength + 7) / 8)
                throw new InvalidOperationException("Insufficient entropy provided by entropy source");
			return length;
        }

		private int GetEntropyLength()
		{
			return (mEntropySource.EntropySize + 7) / 8;
		}
#endif

        // -- Internal state migration ---

        private static readonly byte[] K_BITS = Hex.DecodeStrict(
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

        // 1. If (number_of_bits_to_return > max_number_of_bits), then return an
        // ERROR_FLAG.
        // 2. L = len (input_string)/8.
        // 3. N = number_of_bits_to_return/8.
        // Comment: L is the bitstring represention of
        // the integer resulting from len (input_string)/8.
        // L shall be represented as a 32-bit integer.
        //
        // Comment : N is the bitstring represention of
        // the integer resulting from
        // number_of_bits_to_return/8. N shall be
        // represented as a 32-bit integer.
        //
        // 4. S = L || N || input_string || 0x80.
        // 5. While (len (S) mod outlen)
        // Comment : Pad S with zeros, if necessary.
        // 0, S = S || 0x00.
        //
        // Comment : Compute the starting value.
        // 6. temp = the Null string.
        // 7. i = 0.
        // 8. K = Leftmost keylen bits of 0x00010203...1D1E1F.
        // 9. While len (temp) < keylen + outlen, do
        //
        // IV = i || 0outlen - len (i).
        //
        // 9.1
        //
        // temp = temp || BCC (K, (IV || S)).
        //
        // 9.2
        //
        // i = i + 1.
        //
        // 9.3
        //
        // Comment : i shall be represented as a 32-bit
        // integer, i.e., len (i) = 32.
        //
        // Comment: The 32-bit integer represenation of
        // i is padded with zeros to outlen bits.
        //
        // Comment: Compute the requested number of
        // bits.
        //
        // 10. K = Leftmost keylen bits of temp.
        //
        // 11. X = Next outlen bits of temp.
        //
        // 12. temp = the Null string.
        //
        // 13. While len (temp) < number_of_bits_to_return, do
        //
        // 13.1 X = Block_Encrypt (K, X).
        //
        // 13.2 temp = temp || X.
        //
        // 14. requested_bits = Leftmost number_of_bits_to_return of temp.
        //
        // 15. Return SUCCESS and requested_bits.
		private byte[] BlockCipherDF(byte[] input, int N)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return BlockCipherDF(input.AsSpan(), N);
#else
            int outLen = mEngine.GetBlockSize();
	        int L = input.Length; // already in bytes
	        // 4 S = L || N || input || 0x80
	        int sLen = 4 + 4 + L + 1;
	        int blockLen = ((sLen + outLen - 1) / outLen) * outLen;
	        byte[] S = new byte[blockLen];
            Pack.UInt32_To_BE((uint)L, S, 0);
            Pack.UInt32_To_BE((uint)N, S, 4);
			Array.Copy(input, 0, S, 8, L);
	        S[8 + L] = 0x80;
	        // S already padded with zeros

	        byte[] temp = new byte[mKeySizeInBits / 8 + outLen];
	        byte[] bccOut = new byte[outLen];

	        byte[] IV = new byte[outLen]; 
	        
	        int i = 0;
	        byte[] K = new byte[mKeySizeInBits / 8];
	        Array.Copy(K_BITS, 0, K, 0, K.Length);
            var K1 = ExpandToKeyParameter(K);
	        mEngine.Init(true, K1);

	        while (i*outLen*8 < mKeySizeInBits + outLen *8)
	        {
                Pack.UInt32_To_BE((uint)i, IV, 0);
                BCC(bccOut, IV, S);

                int bytesToCopy = System.Math.Min(outLen, temp.Length - i * outLen);
	            Array.Copy(bccOut, 0, temp, i * outLen, bytesToCopy);
	            ++i;
	        }

	        byte[] X = new byte[outLen];
	        Array.Copy(temp, 0, K, 0, K.Length);
	        Array.Copy(temp, K.Length, X, 0, X.Length);

	        temp = new byte[N];

	        i = 0;
	        mEngine.Init(true, ExpandToKeyParameter(K));

	        while (i * outLen < temp.Length)
	        {
	            mEngine.ProcessBlock(X, 0, X, 0);

				int bytesToCopy = System.Math.Min(outLen, temp.Length - i * outLen);
	            Array.Copy(X, 0, temp, i * outLen, bytesToCopy);
	            i++;
	        }

	        return temp;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private byte[] BlockCipherDF(ReadOnlySpan<byte> input, int N)
        {
            int blockSize = mEngine.GetBlockSize();
            int L = input.Length; // already in bytes
            // 4 S = L || N || input || 0x80
            int sLen = 4 + 4 + L + 1;
            int blockLen = ((sLen + blockSize - 1) / blockSize) * blockSize;
            Span<byte> S = blockLen <= 256
                ? stackalloc byte[blockLen]
                : new byte[blockLen];
            Pack.UInt32_To_BE((uint)L, S);
            Pack.UInt32_To_BE((uint)N, S[4..]);
            input.CopyTo(S[8..]);
            S[8 + L] = 0x80;
            // S already padded with zeros

            int keySize = mKeySizeInBits / 8;
            int tempSize = keySize + blockSize;
            Span<byte> temp = tempSize <= 128
                ? stackalloc byte[tempSize]
                : new byte[tempSize];

            Span<byte> bccOut = blockSize <= 64
                ? stackalloc byte[blockSize]
                : new byte[blockSize];

            Span<byte> IV = blockSize <= 64
                ? stackalloc byte[blockSize]
                : new byte[blockSize];

            var K1 = ExpandToKeyParameter(K_BITS.AsSpan(0, keySize));
            mEngine.Init(true, K1);

            for (int i = 0; i * blockSize < tempSize; ++i)
            {
                Pack.UInt32_To_BE((uint)i, IV);
                BCC(bccOut, IV, S);

                int bytesToCopy = System.Math.Min(blockSize, tempSize - i * blockSize);
                bccOut[..bytesToCopy].CopyTo(temp[(i * blockSize)..]);
            }

            var K2 = ExpandToKeyParameter(temp[..keySize]);
            mEngine.Init(true, K2);
            var X = temp[keySize..];

            byte[] result = new byte[N];
            for (int i = 0; i * blockSize < result.Length; ++i)
            {
                mEngine.ProcessBlock(X, X);

                int bytesToCopy = System.Math.Min(blockSize, result.Length - i * blockSize);
                X[..bytesToCopy].CopyTo(result.AsSpan(i * blockSize));
            }
            return result;
        }
#endif

        /*
        * 1. chaining_value = 0^outlen    
        *    . Comment: Set the first chaining value to outlen zeros.
        * 2. n = len (data)/outlen.
        * 3. Starting with the leftmost bits of data, split the data into n blocks of outlen bits 
        *    each, forming block(1) to block(n). 
        * 4. For i = 1 to n do
        * 4.1 input_block = chaining_value ^ block(i) .
        * 4.2 chaining_value = Block_Encrypt (Key, input_block).
        * 5. output_block = chaining_value.
        * 6. Return output_block. 
        */
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void BCC(Span<byte> bccOut, ReadOnlySpan<byte> iV, ReadOnlySpan<byte> data)
        {
            int blockSize = mEngine.GetBlockSize();

            Span<byte> chainingValue = blockSize <= 64
                ? stackalloc byte[blockSize]
                : new byte[blockSize];
            Span<byte> inputBlock = blockSize <= 64
                ? stackalloc byte[blockSize]
                : new byte[blockSize];

            mEngine.ProcessBlock(iV, chainingValue);

            int n = data.Length / blockSize;
            for (int i = 0; i < n; i++)
            {
                Xor(chainingValue, data[(i * blockSize)..], inputBlock);
                mEngine.ProcessBlock(inputBlock, chainingValue);
            }

            bccOut.CopyFrom(chainingValue);
        }
#else
        private void BCC(byte[] bccOut, byte[] iV, byte[] data)
	    {
	        int outlen = mEngine.GetBlockSize();
	        byte[] chainingValue = new byte[outlen]; // initial values = 0
	        int n = data.Length / outlen;

	        byte[] inputBlock = new byte[outlen];

            mEngine.ProcessBlock(iV, 0, chainingValue, 0);

            for (int i = 0; i < n; i++)
	        {
	            Xor(inputBlock, chainingValue, data, i*outlen);
	            mEngine.ProcessBlock(inputBlock, 0, chainingValue, 0);
	        }

            Array.Copy(chainingValue, 0, bccOut, 0, bccOut.Length);
	    }
#endif

        /**
	     * Return the block size (in bits) of the DRBG.
	     *
	     * @return the number of bits produced on each internal round of the DRBG.
	     */
        public int BlockSize
	    {
			get { return mV.Length * 8; }
	    }

	    /**
	     * Populate a passed in array with random data.
	     *
	     * @param output output array for generated bits.
	     * @param additionalInput additional input to be added to the DRBG in this step.
	     * @param predictionResistant true if a reseed should be forced, false otherwise.
	     *
	     * @return number of bits generated, -1 if a reseed required.
	     */
	    public int Generate(byte[] output, int outputOff, int outputLen, byte[] additionalInput,
			bool predictionResistant)
	    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return additionalInput == null
                ? Generate(output.AsSpan(outputOff, outputLen), predictionResistant)
                : GenerateWithInput(output.AsSpan(outputOff, outputLen), additionalInput.AsSpan(), predictionResistant);
#else
			if (mIsTdea)
	        {
	            if (mReseedCounter > TDEA_RESEED_MAX)
	                return -1;

                if (outputLen > TDEA_MAX_BITS_REQUEST / 8)
	                throw new ArgumentException("Number of bits per request limited to " + TDEA_MAX_BITS_REQUEST, "output");
	        }
	        else
	        {
	            if (mReseedCounter > AES_RESEED_MAX)
	                return -1;

                if (outputLen > AES_MAX_BITS_REQUEST / 8)
	                throw new ArgumentException("Number of bits per request limited to " + AES_MAX_BITS_REQUEST, "output");
	        }

            if (predictionResistant)
	        {
	            CTR_DRBG_Reseed_algorithm(additionalInput);
	            additionalInput = null;
	        }

	        if (additionalInput != null)
	        {
	            additionalInput = BlockCipherDF(additionalInput, mSeedLength / 8);
	            CTR_DRBG_Update(additionalInput, mKey, mV);
	        }
	        else
	        {
	            additionalInput = new byte[mSeedLength];
	        }

            byte[] tmp = new byte[mV.Length];

            mEngine.Init(true, ExpandToKeyParameter(mKey));

            for (int i = 0, limit = outputLen / tmp.Length; i <= limit; i++)
	        {
				int bytesToCopy = System.Math.Min(tmp.Length, outputLen - i * tmp.Length);

                if (bytesToCopy != 0)
	            {
	                AddOneTo(mV);

                    mEngine.ProcessBlock(mV, 0, tmp, 0);

                    Array.Copy(tmp, 0, output, outputOff + i * tmp.Length, bytesToCopy);
	            }
	        }

            CTR_DRBG_Update(additionalInput, mKey, mV);

            mReseedCounter++;

            return outputLen * 8;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Generate(Span<byte> output, bool predictionResistant)
        {
            int outputLen = output.Length;
            if (mIsTdea)
            {
                if (mReseedCounter > TDEA_RESEED_MAX)
                    return -1;

                if (outputLen > TDEA_MAX_BITS_REQUEST / 8)
                    throw new ArgumentException("Number of bits per request limited to " + TDEA_MAX_BITS_REQUEST, "output");
            }
            else
            {
                if (mReseedCounter > AES_RESEED_MAX)
                    return -1;

                if (outputLen > AES_MAX_BITS_REQUEST / 8)
                    throw new ArgumentException("Number of bits per request limited to " + AES_MAX_BITS_REQUEST, "output");
            }

            if (predictionResistant)
            {
                CTR_DRBG_Reseed_algorithm(ReadOnlySpan<byte>.Empty);
            }

            byte[] seed = new byte[mSeedLength / 8];

            return ImplGenerate(seed, output);
        }

        public int GenerateWithInput(Span<byte> output, ReadOnlySpan<byte> additionalInput, bool predictionResistant)
		{
			int outputLen = output.Length;
            if (mIsTdea)
            {
                if (mReseedCounter > TDEA_RESEED_MAX)
                    return -1;

                if (outputLen > TDEA_MAX_BITS_REQUEST / 8)
                    throw new ArgumentException("Number of bits per request limited to " + TDEA_MAX_BITS_REQUEST, "output");
            }
            else
            {
                if (mReseedCounter > AES_RESEED_MAX)
                    return -1;

                if (outputLen > AES_MAX_BITS_REQUEST / 8)
                    throw new ArgumentException("Number of bits per request limited to " + AES_MAX_BITS_REQUEST, "output");
            }

            int seedLength = mSeedLength / 8;
            byte[] seed;
            if (predictionResistant)
            {
                CTR_DRBG_Reseed_algorithm(additionalInput);
                seed = new byte[seedLength];
            }
            else
			{
                seed = BlockCipherDF(additionalInput, seedLength);
                CTR_DRBG_Update(seed, mKey, mV);
            }

			return ImplGenerate(seed, output);
        }

		private int ImplGenerate(ReadOnlySpan<byte> seed, Span<byte> output)
		{
            byte[] tmp = new byte[mV.Length];

            mEngine.Init(true, ExpandToKeyParameter(mKey));

            int outputLen = output.Length;
            for (int i = 0, limit = outputLen / tmp.Length; i <= limit; i++)
            {
                int bytesToCopy = System.Math.Min(tmp.Length, outputLen - i * tmp.Length);

                if (bytesToCopy != 0)
                {
                    AddOneTo(mV);

                    mEngine.ProcessBlock(mV, 0, tmp, 0);

                    tmp[..bytesToCopy].CopyTo(output[(i * tmp.Length)..]);
                }
            }

            CTR_DRBG_Update(seed, mKey, mV);

            mReseedCounter++;

            return outputLen * 8;
        }
#endif

        /**
	      * Reseed the DRBG.
	      *
	      * @param additionalInput additional input to be added to the DRBG in this step.
	      */
        public void Reseed(byte[] additionalInput)
	    {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
			Reseed(Spans.FromNullableReadOnly(additionalInput));
#else
			CTR_DRBG_Reseed_algorithm(additionalInput);
#endif
	    }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Reseed(ReadOnlySpan<byte> additionalInput)
		{
            CTR_DRBG_Reseed_algorithm(additionalInput);
        }
#endif

        private bool IsTdea(IBlockCipher cipher)
	    {
	        return cipher.AlgorithmName.Equals("DESede") || cipher.AlgorithmName.Equals("TDEA");
	    }

	    private int GetMaxSecurityStrength(IBlockCipher cipher, int keySizeInBits)
	    {
	        if (IsTdea(cipher) && keySizeInBits == 168)
	        {
	            return 112;
	        }
	        if (cipher.AlgorithmName.Equals("AES"))
	        {
	            return keySizeInBits;
	        }

            return -1;
	    }

        private KeyParameter ExpandToKeyParameter(byte[] key)
	    {
			if (!mIsTdea)
				return new KeyParameter(key);

	        // expand key to 192 bits.
	        byte[] tmp = new byte[24];

            PadKey(key, 0, tmp, 0);
            PadKey(key, 7, tmp, 8);
            PadKey(key, 14, tmp, 16);

            return new KeyParameter(tmp);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private KeyParameter ExpandToKeyParameter(ReadOnlySpan<byte> key)
        {
			if (!mIsTdea)
				return new KeyParameter(key);

            // expand key to 192 bits.
            Span<byte> tmp = stackalloc byte[24];

            PadKey(key, tmp);
			PadKey(key[7..], tmp[8..]);
			PadKey(key[14..], tmp[16..]);

            return new KeyParameter(tmp);
        }
#endif

        /**
	     * Pad out a key for TDEA, setting odd parity for each byte.
	     *
	     * @param keyMaster
	     * @param keyOff
	     * @param tmp
	     * @param tmpOff
	     */
        private void PadKey(byte[] keyMaster, int keyOff, byte[] tmp, int tmpOff)
	    {
	        tmp[tmpOff + 0] = (byte)(keyMaster[keyOff + 0] & 0xfe);
	        tmp[tmpOff + 1] = (byte)((keyMaster[keyOff + 0] << 7) | ((keyMaster[keyOff + 1] & 0xfc) >> 1));
	        tmp[tmpOff + 2] = (byte)((keyMaster[keyOff + 1] << 6) | ((keyMaster[keyOff + 2] & 0xf8) >> 2));
	        tmp[tmpOff + 3] = (byte)((keyMaster[keyOff + 2] << 5) | ((keyMaster[keyOff + 3] & 0xf0) >> 3));
	        tmp[tmpOff + 4] = (byte)((keyMaster[keyOff + 3] << 4) | ((keyMaster[keyOff + 4] & 0xe0) >> 4));
	        tmp[tmpOff + 5] = (byte)((keyMaster[keyOff + 4] << 3) | ((keyMaster[keyOff + 5] & 0xc0) >> 5));
	        tmp[tmpOff + 6] = (byte)((keyMaster[keyOff + 5] << 2) | ((keyMaster[keyOff + 6] & 0x80) >> 6));
	        tmp[tmpOff + 7] = (byte)(keyMaster[keyOff + 6] << 1);

            DesParameters.SetOddParity(tmp, tmpOff, 8);
	    }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void PadKey(ReadOnlySpan<byte> keyMaster, Span<byte> tmp)
        {
            tmp[0] = (byte)(keyMaster[0] & 0xFE);
            tmp[1] = (byte)((keyMaster[0] << 7) | ((keyMaster[1] & 0xfc) >> 1));
            tmp[2] = (byte)((keyMaster[1] << 6) | ((keyMaster[2] & 0xf8) >> 2));
            tmp[3] = (byte)((keyMaster[2] << 5) | ((keyMaster[3] & 0xf0) >> 3));
            tmp[4] = (byte)((keyMaster[3] << 4) | ((keyMaster[4] & 0xe0) >> 4));
            tmp[5] = (byte)((keyMaster[4] << 3) | ((keyMaster[5] & 0xc0) >> 5));
            tmp[6] = (byte)((keyMaster[5] << 2) | ((keyMaster[6] & 0x80) >> 6));
            tmp[7] = (byte)(keyMaster[6] << 1);

			DesParameters.SetOddParity(tmp[..8]);
        }
#endif
    }
}
