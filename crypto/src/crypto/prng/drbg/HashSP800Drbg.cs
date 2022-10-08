using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Prng.Drbg
{
	/**
	 * A SP800-90A Hash DRBG.
	 */
	public sealed class HashSP800Drbg
        :   ISP80090Drbg
	{
	    private readonly static byte[] ONE = { 0x01 };

		private readonly static long RESEED_MAX = 1L << (48 - 1);
		private readonly static int MAX_BITS_REQUEST = 1 << (19 - 1);

		private static readonly IDictionary<string, int> SeedLens =
			new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

		static HashSP800Drbg()
	    {
			SeedLens.Add("SHA-1", 440);
			SeedLens.Add("SHA-224", 440);
			SeedLens.Add("SHA-256", 440);
			SeedLens.Add("SHA-512/256", 440);
			SeedLens.Add("SHA-512/224", 440);
			SeedLens.Add("SHA-384", 888);
			SeedLens.Add("SHA-512", 888);
	    }

        private readonly IDigest        mDigest;
        private readonly IEntropySource mEntropySource;
        private readonly int            mSecurityStrength;
        private readonly int            mSeedLength;

        private byte[] mV;
        private byte[] mC;
        private long mReseedCounter;

        /**
	     * Construct a SP800-90A Hash DRBG.
	     * <p>
	     * Minimum entropy requirement is the security strength requested.
	     * </p>
	     * @param digest  source digest to use for DRB stream.
	     * @param securityStrength security strength required (in bits)
	     * @param entropySource source of entropy to use for seeding/reseeding.
	     * @param personalizationString personalization string to distinguish this DRBG (may be null).
	     * @param nonce nonce to further distinguish this DRBG (may be null).
	     */
	    public HashSP800Drbg(IDigest digest, int securityStrength, IEntropySource entropySource, byte[] personalizationString, byte[] nonce)
	    {
	        if (securityStrength > DrbgUtilities.GetMaxSecurityStrength(digest))
	            throw new ArgumentException("Requested security strength is not supported by the derivation function");
	        if (entropySource.EntropySize < securityStrength)
	            throw new ArgumentException("Not enough entropy for security strength required");

            mDigest = digest;
	        mEntropySource = entropySource;
	        mSecurityStrength = securityStrength;
            mSeedLength = SeedLens[digest.AlgorithmName];

            // 1. seed_material = entropy_input || nonce || personalization_string.
	        // 2. seed = Hash_df (seed_material, seedlen).
	        // 3. V = seed.
	        // 4. C = Hash_df ((0x00 || V), seedlen). Comment: Preceed V with a byte
	        // of zeros.
	        // 5. reseed_counter = 1.
	        // 6. Return V, C, and reseed_counter as the initial_working_state

	        byte[] entropy = GetEntropy();
	        byte[] seedMaterial = Arrays.ConcatenateAll(entropy, nonce, personalizationString);
            mV = new byte[(mSeedLength + 7) / 8];
            DrbgUtilities.HashDF(mDigest, seedMaterial, mSeedLength, mV);

	        byte[] subV = new byte[mV.Length + 1];
	        Array.Copy(mV, 0, subV, 1, mV.Length);
            mC = new byte[(mSeedLength + 7) / 8];
            DrbgUtilities.HashDF(mDigest, subV, mSeedLength, mC);

            mReseedCounter = 1;
	    }

	    /**
	     * Return the block size (in bits) of the DRBG.
	     *
	     * @return the number of bits produced on each internal round of the DRBG.
	     */
	    public int BlockSize
	    {
			get { return mDigest.GetDigestSize() * 8; }
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
			// 1. If reseed_counter > reseed_interval, then return an indication that a
			// reseed is required.
			// 2. If (additional_input != Null), then do
			// 2.1 w = Hash (0x02 || V || additional_input).
			// 2.2 V = (V + w) mod 2^seedlen
			// .
			// 3. (returned_bits) = Hashgen (requested_number_of_bits, V).
			// 4. H = Hash (0x03 || V).
			// 5. V = (V + H + C + reseed_counter) mod 2^seedlen
			// .
			// 6. reseed_counter = reseed_counter + 1.
			// 7. Return SUCCESS, returned_bits, and the new values of V, C, and
			// reseed_counter for the new_working_state.
			int numberOfBits = outputLen * 8;

	        if (numberOfBits > MAX_BITS_REQUEST)
	            throw new ArgumentException("Number of bits per request limited to " + MAX_BITS_REQUEST, "output");

            if (mReseedCounter > RESEED_MAX)
	            return -1;

            if (predictionResistant)
	        {   
	            Reseed(additionalInput);
	            additionalInput = null;
	        }

	        // 2.
	        if (additionalInput != null)
	        {
	            byte[] newInput = new byte[1 + mV.Length + additionalInput.Length];
	            newInput[0] = 0x02;
	            Array.Copy(mV, 0, newInput, 1, mV.Length);
	            Array.Copy(additionalInput, 0, newInput, 1 + mV.Length, additionalInput.Length);
	            byte[] w = Hash(newInput);

                AddTo(mV, w);
	        }

            // 3.
	        byte[] rv = Hashgen(mV, outputLen);

            // 4.
	        byte[] subH = new byte[mV.Length + 1];
	        Array.Copy(mV, 0, subH, 1, mV.Length);
	        subH[0] = 0x03;

            byte[] H = Hash(subH);

            // 5.
	        AddTo(mV, H);
	        AddTo(mV, mC);

	        byte[] c = new byte[4];
			Pack.UInt32_To_BE((uint)mReseedCounter, c);

	        AddTo(mV, c);

	        mReseedCounter++;

	        Array.Copy(rv, 0, output, outputOff, outputLen);

	        return numberOfBits;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Generate(Span<byte> output, bool predictionResistant)
        {
            // 1. If reseed_counter > reseed_interval, then return an indication that a
            // reseed is required.
            // 2. If (additional_input != Null), then do
            // 2.1 w = Hash (0x02 || V || additional_input).
            // 2.2 V = (V + w) mod 2^seedlen
            // .
            // 3. (returned_bits) = Hashgen (requested_number_of_bits, V).
            // 4. H = Hash (0x03 || V).
            // 5. V = (V + H + C + reseed_counter) mod 2^seedlen
            // .
            // 6. reseed_counter = reseed_counter + 1.
            // 7. Return SUCCESS, returned_bits, and the new values of V, C, and
            // reseed_counter for the new_working_state.
            int numberOfBits = output.Length * 8;

            if (numberOfBits > MAX_BITS_REQUEST)
                throw new ArgumentException("Number of bits per request limited to " + MAX_BITS_REQUEST, "output");

            if (mReseedCounter > RESEED_MAX)
                return -1;

            if (predictionResistant)
            {
                Reseed(ReadOnlySpan<byte>.Empty);
            }

			return ImplGenerate(output);
        }

        public int GenerateWithInput(Span<byte> output, ReadOnlySpan<byte> additionalInput, bool predictionResistant)
		{
			// 1. If reseed_counter > reseed_interval, then return an indication that a
			// reseed is required.
			// 2. If (additional_input != Null), then do
			// 2.1 w = Hash (0x02 || V || additional_input).
			// 2.2 V = (V + w) mod 2^seedlen
			// .
			// 3. (returned_bits) = Hashgen (requested_number_of_bits, V).
			// 4. H = Hash (0x03 || V).
			// 5. V = (V + H + C + reseed_counter) mod 2^seedlen
			// .
			// 6. reseed_counter = reseed_counter + 1.
			// 7. Return SUCCESS, returned_bits, and the new values of V, C, and
			// reseed_counter for the new_working_state.
            int numberOfBits = output.Length * 8;

            if (numberOfBits > MAX_BITS_REQUEST)
                throw new ArgumentException("Number of bits per request limited to " + MAX_BITS_REQUEST, "output");

            if (mReseedCounter > RESEED_MAX)
                return -1;

            if (predictionResistant)
            {
                Reseed(additionalInput);
            }
			else
			{
                // 2.
                mDigest.Update(0x02);
                mDigest.BlockUpdate(mV);
                mDigest.BlockUpdate(additionalInput);

                int digestSize = mDigest.GetDigestSize();
                Span<byte> w = digestSize <= 128
					? stackalloc byte[digestSize]
                    : new byte[digestSize];
                mDigest.DoFinal(w);

                AddTo(mV, w);
            }

			return ImplGenerate(output);
        }

		private int ImplGenerate(Span<byte> output)
		{
            // 3.
            Hashgen(mV, output);

            // 4.
            mDigest.Update(0x03);
            mDigest.BlockUpdate(mV);

            int digestSize = mDigest.GetDigestSize();
            Span<byte> H = digestSize <= 128
                ? stackalloc byte[digestSize]
                : new byte[digestSize];
            mDigest.DoFinal(H);

            // 5.
            AddTo(mV, H);
            AddTo(mV, mC);

			Span<byte> c = stackalloc byte[4];
			Pack.UInt32_To_BE((uint)mReseedCounter, c);

            AddTo(mV, c);

            mReseedCounter++;

            return output.Length * 8;
        }
#endif

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

        // this will always add the shorter length byte array mathematically to the
        // longer length byte array.
        // be careful....
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void AddTo(Span<byte> longer, ReadOnlySpan<byte> shorter)
#else
		private void AddTo(byte[] longer, byte[] shorter)
#endif
        {
            int off = longer.Length - shorter.Length;

            uint carry = 0;
            int i = shorter.Length;
            while (--i >= 0)
            {
                carry += (uint)longer[off + i] + shorter[i];
                longer[off + i] = (byte)carry;
                carry >>= 8;
            }

            i = off;
            while (--i >= 0)
            {
                carry += longer[i];
                longer[i] = (byte)carry;
                carry >>= 8;
            }
	    }

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
			// 1. seed_material = 0x01 || V || entropy_input || additional_input.
			//
			// 2. seed = Hash_df (seed_material, seedlen).
			//
			// 3. V = seed.
			//
			// 4. C = Hash_df ((0x00 || V), seedlen).
			//
			// 5. reseed_counter = 1.
			//
			// 6. Return V, C, and reseed_counter for the new_working_state.
			//
			// Comment: Precede with a byte of all zeros.
			byte[] entropy = GetEntropy();
	        byte[] seedMaterial = Arrays.ConcatenateAll(ONE, mV, entropy, additionalInput);
	        DrbgUtilities.HashDF(mDigest, seedMaterial, mSeedLength, mV);

	        byte[] subV = new byte[mV.Length + 1];
	        subV[0] = 0x00;
	        Array.Copy(mV, 0, subV, 1, mV.Length);
	        DrbgUtilities.HashDF(mDigest, subV, mSeedLength, mC);

            mReseedCounter = 1;
#endif
	    }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void Reseed(ReadOnlySpan<byte> additionalInput)
        {
			// 1. seed_material = 0x01 || V || entropy_input || additional_input.
			//
			// 2. seed = Hash_df (seed_material, seedlen).
			//
			// 3. V = seed.
			//
			// 4. C = Hash_df ((0x00 || V), seedlen).
			//
			// 5. reseed_counter = 1.
			//
			// 6. Return V, C, and reseed_counter for the new_working_state.
			//
			// Comment: Precede with a byte of all zeros.
			int entropyLength = GetEntropyLength();

			int seedMaterialLength = 1 + mV.Length + entropyLength + additionalInput.Length;
			Span<byte> seedMaterial = seedMaterialLength <= 256
				? stackalloc byte[seedMaterialLength]
				: new byte[seedMaterialLength];

			seedMaterial[0] = 0x01;
			mV.CopyTo(seedMaterial[1..]);
			GetEntropy(seedMaterial[(1 + mV.Length)..]);
			additionalInput.CopyTo(seedMaterial[(1 + mV.Length + entropyLength)..]);

            DrbgUtilities.HashDF(mDigest, seedMaterial, mSeedLength, mV);

			int subVLength = 1 + mV.Length;
			Span<byte> subV = subVLength <= 128
				? stackalloc byte[subVLength]
				: new byte[subVLength];
            subV[0] = 0x00;
			mV.CopyTo(subV[1..]);

            DrbgUtilities.HashDF(mDigest, subV, mSeedLength, mC);

            mReseedCounter = 1;
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void DoHash(ReadOnlySpan<byte> input, Span<byte> output)
        {
            mDigest.BlockUpdate(input);
            mDigest.DoFinal(output);
        }
#else
		private void DoHash(byte[] input, byte[] output)
        {
            mDigest.BlockUpdate(input, 0, input.Length);
            mDigest.DoFinal(output, 0);
        }

        private byte[] Hash(byte[] input)
        {
            byte[] hash = new byte[mDigest.GetDigestSize()];
            DoHash(input, hash);
            return hash;
        }
#endif

        // 1. m = [requested_number_of_bits / outlen]
        // 2. data = V.
        // 3. W = the Null string.
        // 4. For i = 1 to m
        // 4.1 wi = Hash (data).
        // 4.2 W = W || wi.
        // 4.3 data = (data + 1) mod 2^seedlen
        // .
        // 5. returned_bits = Leftmost (requested_no_of_bits) bits of W.
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void Hashgen(ReadOnlySpan<byte> input, Span<byte> output)
	    {
	        int digestSize = mDigest.GetDigestSize();
	        int m = output.Length / digestSize;

			int dataSize = input.Length;
            Span<byte> data = dataSize <= 256
				? stackalloc byte[input.Length]
                : new byte[input.Length];
			input.CopyTo(data);

            Span<byte> dig = digestSize <= 128
				? stackalloc byte[digestSize]
                : new byte[digestSize];

	        for (int i = 0; i <= m; i++)
	        {
	            DoHash(data, dig);

				int bytesToCopy = System.Math.Min(digestSize, output.Length - i * digestSize);
				dig[..bytesToCopy].CopyTo(output[(i * digestSize)..]);
                AddTo(data, ONE);
	        }
	    }
#else
        private byte[] Hashgen(byte[] input, int length)
	    {
	        int digestSize = mDigest.GetDigestSize();
	        int m = length / digestSize;

            byte[] data = (byte[])input.Clone();
	        byte[] W = new byte[length];

            byte[] dig = new byte[digestSize];
	        for (int i = 0; i <= m; i++)
	        {
	            DoHash(data, dig);

				int bytesToCopy = System.Math.Min(digestSize, length - i * digestSize);
	            Array.Copy(dig, 0, W, i * digestSize, bytesToCopy);

                AddTo(data, ONE);
	        }

	        return W;
	    }
#endif
    }
}
