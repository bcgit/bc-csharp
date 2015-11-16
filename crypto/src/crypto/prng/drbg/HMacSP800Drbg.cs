using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Prng.Drbg
{
	/**
	 * A SP800-90A HMAC DRBG.
	 */
	public class HMacSP800Drbg: SP80090Drbg
	{
	    private readonly static long       RESEED_MAX = 1L << (48 - 1);
		private readonly static int        MAX_BITS_REQUEST = 1 << (19 - 1);

	    private byte[] _K;
	    private byte[] _V;
	    private long   _reseedCounter;
	    private EntropySource _entropySource;
	    private Mac _hMac;
	    private int _securityStrength;

	    /**
	     * Construct a SP800-90A Hash DRBG.
	     * <p>
	     * Minimum entropy requirement is the security strength requested.
	     * </p>
	     * @param hMac Hash MAC to base the DRBG on.
	     * @param securityStrength security strength required (in bits)
	     * @param entropySource source of entropy to use for seeding/reseeding.
	     * @param personalizationString personalization string to distinguish this DRBG (may be null).
	     * @param nonce nonce to further distinguish this DRBG (may be null).
	     */
	    public HMacSP800Drbg(IMac hMac, int securityStrength, IEntropySource entropySource, byte[] personalizationString, byte[] nonce)
	    {
	        if (securityStrength > Utils.getMaxSecurityStrength(hMac))
	        {
	            throw new ArgumentException("Requested security strength is not supported by the derivation function");
	        }

	        if (entropySource.EntropySize < securityStrength)
	        {
	            throw new ArgumentException("Not enough entropy for security strength required");
	        }

	        _securityStrength = securityStrength;
	        _entropySource = entropySource;
	        _hMac = hMac;

	        byte[] entropy = getEntropy();
	        byte[] seedMaterial = Arrays.Concatenate(entropy, nonce, personalizationString);

	        _K = new byte[hMac.GetMacSize()];
	        _V = new byte[_K.Length];
	        Arrays.fill(_V, (byte)1);

	        hmac_DRBG_Update(seedMaterial);

	        _reseedCounter = 1;
	    }

	    private void hmac_DRBG_Update(byte[] seedMaterial)
	    {
	        hmac_DRBG_Update_Func(seedMaterial, (byte)0x00);
	        if (seedMaterial != null)
	        {
	            hmac_DRBG_Update_Func(seedMaterial, (byte)0x01);
	        }
	    }

	    private void hmac_DRBG_Update_Func(byte[] seedMaterial, byte vValue)
	    {
	        _hMac.Init(new KeyParameter(_K));

	        _hMac.BlockUpdate(_V, 0, _V.Length);
	        _hMac.Update(vValue);

	        if (seedMaterial != null)
	        {
	            _hMac.update(seedMaterial, 0, seedMaterial.Length);
	        }

	        _hMac.DoFinal(_K, 0);

	        _hMac.Init(new KeyParameter(_K));
	        _hMac.BlockUpdate(_V, 0, _V.Length);

	        _hMac.DoFinal(_V, 0);
	    }

	    /**
	     * Return the block size (in bits) of the DRBG.
	     *
	     * @return the number of bits produced on each round of the DRBG.
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
	    public int Generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
	    {
	        int numberOfBits = output.Length * 8;

	        if (numberOfBits > MAX_BITS_REQUEST)
	        {
	            throw new IllegalArgumentException("Number of bits per request limited to " + MAX_BITS_REQUEST);
	        }

	        if (_reseedCounter > RESEED_MAX)
	        {
	            return -1;
	        }

	        if (predictionResistant)
	        {
	            reseed(additionalInput);
	            additionalInput = null;
	        }

	        // 2.
	        if (additionalInput != null)
	        {
	            hmac_DRBG_Update(additionalInput);
	        }

	        // 3.
	        byte[] rv = new byte[output.Length];

	        int m = output.Length / _V.Length;

	        _hMac.Init(new KeyParameter(_K));

	        for (int i = 0; i < m; i++)
	        {
	            _hMac.BlockUpdate(_V, 0, _V.Length);
	            _hMac.DoFinal(_V, 0);

	            Array.Copy(_V, 0, rv, i * _V.Length, _V.Length);
	        }

	        if (m * _V.Length < rv.Length)
	        {
					_hMac.BlockUpdate(_V, 0, _V.Length);
	            _hMac.DoFinal(_V, 0);

	            Array.Copy(_V, 0, rv, m * _V.Length, rv.Length - (m * _V.Length));
	        }

	        hmac_DRBG_Update(additionalInput);

	        _reseedCounter++;

	        Array.Copy(rv, 0, output, 0, output.Length);

	        return numberOfBits;
	    }

	    /**
	      * Reseed the DRBG.
	      *
	      * @param additionalInput additional input to be added to the DRBG in this step.
	      */
	    public void Reseed(byte[] additionalInput)
	    {
	        byte[] entropy = getEntropy();
	        byte[] seedMaterial = Arrays.Concatenate(entropy, additionalInput);

	        hmac_DRBG_Update(seedMaterial);

	        _reseedCounter = 1;
	    }

	    private byte[] getEntropy()
	    {
	        byte[] entropy = _entropySource.GetEntropy();

	        if (entropy.Length < (_securityStrength + 7) / 8)
	        {
	            throw new IllegalStateException("Insufficient entropy provided by entropy source");
	        }
	        return entropy;
	    }
	}
}
