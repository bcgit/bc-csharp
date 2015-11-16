using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Prng.Drbg
{
	/**
	 * A SP800-90A CTR DRBG.
	 */
	public class CtrSP800Drbg: SP80090Drbg
	{
	    private static readonly long       TDEA_RESEED_MAX = 1L << (32 - 1);
		private static readonly long       AES_RESEED_MAX = 1L << (48 - 1);
		private static readonly int        TDEA_MAX_BITS_REQUEST = 1 << (13 - 1);
		private static readonly int        AES_MAX_BITS_REQUEST = 1 << (19 - 1);

	    private IEntropySource        _entropySource;
	    private IBlockCipher          _engine;
	    private int                   _keySizeInBits;
	    private int                   _seedLength;
	    private int                   _securityStrength;

	    // internal state
	    private byte[]                _Key;
	    private byte[]                _V;
	    private long                  _reseedCounter = 0;
	    private bool                  _isTDEA = false;

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
	    public CtrSP800Drbg(IBlockCipher engine, int keySizeInBits, int securityStrength, IEntropySource entropySource, byte[] personalizationString, byte[] nonce)
	    {
	        _entropySource = entropySource;
	        _engine = engine;     
	        
	        _keySizeInBits = keySizeInBits;
	        _securityStrength = securityStrength;
	        _seedLength = keySizeInBits + engine.GetBlockSize() * 8;
	        _isTDEA = isTDEA(engine);

	        if (securityStrength > 256)
	        {
	            throw new ArgumentException("Requested security strength is not supported by the derivation function");
	        }

	        if (getMaxSecurityStrength(engine, keySizeInBits) < securityStrength)
	        {
	            throw new ArgumentException("Requested security strength is not supported by block cipher and key size");
	        }

	        if (entropySource.EntropySize < securityStrength)
	        {
	            throw new ArgumentException("Not enough entropy for security strength required");
	        }

	        byte[] entropy = getEntropy();  // Get_entropy_input

	        CTR_DRBG_Instantiate_algorithm(entropy, nonce, personalizationString);
	    }

	    private void CTR_DRBG_Instantiate_algorithm(byte[] entropy, byte[] nonce,
	            byte[] personalisationString)
	    {
	        byte[] seedMaterial = Arrays.Concatenate(entropy, nonce, personalisationString);
	        byte[] seed = Block_Cipher_df(seedMaterial, _seedLength);

	        int outlen = _engine.GetBlockSize();

	        _Key = new byte[(_keySizeInBits + 7) / 8];
	        _V = new byte[outlen];

	         // _Key & _V are modified by this call
	        CTR_DRBG_Update(seed, _Key, _V); 

	        _reseedCounter = 1;
	    }

	    private void CTR_DRBG_Update(byte[] seed, byte[] key, byte[] v)
	    {
	        byte[] temp = new byte[seed.Length];
	        byte[] outputBlock = new byte[_engine.GetBlockSize()];
	        
	        int i=0;
	        int outLen = _engine.GetBlockSize();

	        _engine.Init(true, new KeyParameter(expandKey(key)));
	        while (i*outLen < seed.Length)
	        {
	            addOneTo(v);
	            _engine.ProcessBlock(v, 0, outputBlock, 0);

	            int bytesToCopy = ((temp.Length - i * outLen) > outLen)
	                    ? outLen : (temp.Length - i * outLen);
	            
	            Array.Copy(outputBlock, 0, temp, i * outLen, bytesToCopy);
	            ++i;
	        }

	        XOR(temp, seed, temp, 0);

	        Array.Copy(temp, 0, key, 0, key.Length);
	        Array.Copy(temp, key.Length, v, 0, v.Length);
	    }
	    
	    private void CTR_DRBG_Reseed_algorithm(byte[] additionalInput)
	    {
	        byte[] seedMaterial = Arrays.Concatenate(getEntropy(), additionalInput);

	        seedMaterial = Block_Cipher_df(seedMaterial, _seedLength);

	        CTR_DRBG_Update(seedMaterial, _Key, _V);

	        _reseedCounter = 1;
	    }

	    private void XOR(byte[] output, byte[] a, byte[] b, int bOff)
	    {
				for (int i=0; i< output.Length; i++) 
	        {
					output[i] = (byte)(a[i] ^ b[i+bOff]);
	        }
	    }
	    
	    private void addOneTo(byte[] longer)
	    {
	        int carry = 1;
	        for (int i = 1; i <= longer.Length; i++) // warning
	        {
	            int res = (longer[longer.Length - i] & 0xff) + carry;
	            carry = (res > 0xff) ? 1 : 0;
	            longer[longer.Length - i] = (byte)res;
	        }
	    } 

	    private byte[] getEntropy()
	    {
	        byte[] entropy = _entropySource.GetEntropy();
	        if (entropy.Length < (_securityStrength + 7) / 8)
	        {
	            throw new InvalidOperationException("Insufficient entropy provided by entropy source");
	        }
	        return entropy;
	    }

	    // -- Internal state migration ---
	    
	    private static readonly byte[] K_BITS = Hex.Decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");

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
	    private byte[] Block_Cipher_df(byte[] inputString, int bitLength)
	    {
	        int outLen = _engine.GetBlockSize();
	        int L = inputString.Length; // already in bytes
	        int N = bitLength / 8;
	        // 4 S = L || N || inputstring || 0x80
	        int sLen = 4 + 4 + L + 1;
	        int blockLen = ((sLen + outLen - 1) / outLen) * outLen;
	        byte[] S = new byte[blockLen];
	        copyIntToByteArray(S, L, 0);
	        copyIntToByteArray(S, N, 4);
	        Array.Copy(inputString, 0, S, 8, L);
	        S[8 + L] = (byte)0x80;
	        // S already padded with zeros

	        byte[] temp = new byte[_keySizeInBits / 8 + outLen];
	        byte[] bccOut = new byte[outLen];

	        byte[] IV = new byte[outLen]; 
	        
	        int i = 0;
	        byte[] K = new byte[_keySizeInBits / 8];
	        Array.Copy(K_BITS, 0, K, 0, K.Length);

	        while (i*outLen*8 < _keySizeInBits + outLen *8)
	        {
	            copyIntToByteArray(IV, i, 0);
	            BCC(bccOut, K, IV, S);

	            int bytesToCopy = ((temp.Length - i * outLen) > outLen)
	                    ? outLen
	                    : (temp.Length - i * outLen);
	            
	            Array.Copy(bccOut, 0, temp, i * outLen, bytesToCopy);
	            ++i;
	        }

	        byte[] X = new byte[outLen];
	        Array.Copy(temp, 0, K, 0, K.Length);
	        Array.Copy(temp, K.Length, X, 0, X.Length);

	        temp = new byte[bitLength / 2];

	        i = 0;
	        _engine.Init(true, new KeyParameter(expandKey(K)));

	        while (i * outLen < temp.Length)
	        {
	            _engine.ProcessBlock(X, 0, X, 0);

	            int bytesToCopy = ((temp.Length - i * outLen) > outLen)
	                    ? outLen
	                    : (temp.Length - i * outLen);

	            Array.Copy(X, 0, temp, i * outLen, bytesToCopy);
	            i++;
	        }

	        return temp;
	    }

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
	    private void BCC(byte[] bccOut, byte[] k, byte[] iV, byte[] data)
	    {
	        int outlen = _engine.GetBlockSize();
	        byte[] chainingValue = new byte[outlen]; // initial values = 0
	        int n = data.Length / outlen;

	        byte[] inputBlock = new byte[outlen];

	        _engine.Init(true, new KeyParameter(expandKey(k)));

	        _engine.ProcessBlock(iV, 0, chainingValue, 0);

	        for (int i = 0; i < n; i++)
	        {
	            XOR(inputBlock, chainingValue, data, i*outlen);
	            _engine.ProcessBlock(inputBlock, 0, chainingValue, 0);
	        }

	        Array.Copy(chainingValue, 0, bccOut, 0, bccOut.Length);
	    }

	    private void copyIntToByteArray(byte[] buf, int value, int offSet)
	    {
	        buf[offSet + 0] = ((byte)(value >> 24));
	        buf[offSet + 1] = ((byte)(value >> 16));
	        buf[offSet + 2] = ((byte)(value >> 8));
	        buf[offSet + 3] = ((byte)(value));
	    }

	    /**
	     * Return the block size (in bits) of the DRBG.
	     *
	     * @return the number of bits produced on each internal round of the DRBG.
	     */
	    public int BlockSize
	    {
			get {
				return _V.Length * 8;
			}
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
	    public int Generate(byte[] output, byte[] additionalInput, bool predictionResistant)
	    {
	        if (_isTDEA)
	        {
	            if (_reseedCounter > TDEA_RESEED_MAX)
	            {
	                return -1;
	            }

	            if (Utils.isTooLarge(output, TDEA_MAX_BITS_REQUEST / 8))
	            {
	                throw new ArgumentException("Number of bits per request limited to " + TDEA_MAX_BITS_REQUEST);
	            }
	        }
	        else
	        {
	            if (_reseedCounter > AES_RESEED_MAX)
	            {
	                return -1;
	            }

	            if (Utils.isTooLarge(output, AES_MAX_BITS_REQUEST / 8))
	            {
	                throw new ArgumentException("Number of bits per request limited to " + AES_MAX_BITS_REQUEST);
	            }
	        }

	        if (predictionResistant)
	        {
	            CTR_DRBG_Reseed_algorithm(additionalInput);
	            additionalInput = null;
	        }

	        if (additionalInput != null)
	        {
	            additionalInput = Block_Cipher_df(additionalInput, _seedLength);
	            CTR_DRBG_Update(additionalInput, _Key, _V);
	        }
	        else
	        {
	            additionalInput = new byte[_seedLength];
	        }

	        byte[] tmp = new byte[_V.Length];

	        _engine.Init(true, new KeyParameter(expandKey(_Key)));

				for (int i = 0; i <= output.Length / tmp.Length; i++)
	        {
					int bytesToCopy = ((output.Length - i * tmp.Length) > tmp.Length)
						? tmp.Length
	                    : (output.Length - i * _V.Length);

	            if (bytesToCopy != 0)
	            {
	                addOneTo(_V);

						_engine.ProcessBlock(_V, 0, tmp, 0);

						Array.Copy(tmp, 0, output, i * tmp.Length, bytesToCopy);
	            }
	        }

	        CTR_DRBG_Update(additionalInput, _Key, _V);

	        _reseedCounter++;

	        return output.Length * 8;
	    }

	    /**
	      * Reseed the DRBG.
	      *
	      * @param additionalInput additional input to be added to the DRBG in this step.
	      */
	    public void Reseed(byte[] additionalInput)
	    {
	        CTR_DRBG_Reseed_algorithm(additionalInput);
	    }

	    private bool isTDEA(IBlockCipher cipher)
	    {
	        return cipher.AlgorithmName.Equals("DESede") || cipher.AlgorithmName.Equals("TDEA");
	    }

	    private int getMaxSecurityStrength(IBlockCipher cipher, int keySizeInBits)
	    {
	        if (isTDEA(cipher) && keySizeInBits == 168)
	        {
	            return 112;
	        }
	        if (cipher.AlgorithmName.Equals("AES"))
	        {
	            return keySizeInBits;
	        }

	        return -1;
	    }

	    byte[] expandKey(byte[] key)
	    {
	        if (_isTDEA)
	        {
	            // expand key to 192 bits.
	            byte[] tmp = new byte[24];

	            padKey(key, 0, tmp, 0);
	            padKey(key, 7, tmp, 8);
	            padKey(key, 14, tmp, 16);

	            return tmp;
	        }
	        else
	        {
	            return key;
	        }
	    }

	    /**
	     * Pad out a key for TDEA, setting odd parity for each byte.
	     *
	     * @param keyMaster
	     * @param keyOff
	     * @param tmp
	     * @param tmpOff
	     */
	    private void padKey(byte[] keyMaster, int keyOff, byte[] tmp, int tmpOff)
	    {
	        tmp[tmpOff + 0] = (byte)(keyMaster[keyOff + 0] & 0xfe);
	        tmp[tmpOff + 1] = (byte)((keyMaster[keyOff + 0] << 7) | ((keyMaster[keyOff + 1] & 0xfc) >> 1));
	        tmp[tmpOff + 2] = (byte)((keyMaster[keyOff + 1] << 6) | ((keyMaster[keyOff + 2] & 0xf8) >> 2));
	        tmp[tmpOff + 3] = (byte)((keyMaster[keyOff + 2] << 5) | ((keyMaster[keyOff + 3] & 0xf0) >> 3));
	        tmp[tmpOff + 4] = (byte)((keyMaster[keyOff + 3] << 4) | ((keyMaster[keyOff + 4] & 0xe0) >> 4));
	        tmp[tmpOff + 5] = (byte)((keyMaster[keyOff + 4] << 3) | ((keyMaster[keyOff + 5] & 0xc0) >> 5));
	        tmp[tmpOff + 6] = (byte)((keyMaster[keyOff + 5] << 2) | ((keyMaster[keyOff + 6] & 0x80) >> 6));
	        tmp[tmpOff + 7] = (byte)(keyMaster[keyOff + 6] << 1);

	        for (int i = tmpOff; i <= tmpOff + 7; i++)
	        {
	            int b = tmp[i];
	            tmp[i] = (byte)((b & 0xfe) |
	                            ((((b >> 1) ^
	                            (b >> 2) ^
	                            (b >> 3) ^
	                            (b >> 4) ^
	                            (b >> 5) ^
	                            (b >> 6) ^
	                            (b >> 7)) ^ 0x01) & 0x01));
	        }
	    }
	}
}
