using System;
using System.Collections;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Prng.Drbg
{
	internal class Utils
	{
		private static readonly IDictionary maxSecurityStrengths = Platform.CreateHashtable();

		static Utils()
	    {
	        maxSecurityStrengths.put("SHA-1", 128);

	        maxSecurityStrengths.put("SHA-224", 192);
	        maxSecurityStrengths.put("SHA-256", 256);
	        maxSecurityStrengths.put("SHA-384", 256);
	        maxSecurityStrengths.put("SHA-512", 256);

	        maxSecurityStrengths.put("SHA-512/224", 192);
	        maxSecurityStrengths.put("SHA-512/256", 256);
	    }

	    internal static int getMaxSecurityStrength(IDigest d)
	    {
	        return (int)maxSecurityStrengths[d.AlgorithmName];
	    }

		internal static int getMaxSecurityStrength(IMac m)
	    {
	        String name = m.getAlgorithmName();

	        return (int)maxSecurityStrengths[name.substring(0, name.indexOf("/"))];
	    }

	    /**
	     * Used by both Dual EC and Hash.
	     */
	    internal static byte[] hash_df(Digest digest, byte[] seedMaterial, int seedLength)
	    {
	         // 1. temp = the Null string.
	        // 2. .
	        // 3. counter = an 8-bit binary value representing the integer "1".
	        // 4. For i = 1 to len do
	        // Comment : In step 4.1, no_of_bits_to_return
	        // is used as a 32-bit string.
	        // 4.1 temp = temp || Hash (counter || no_of_bits_to_return ||
	        // input_string).
	        // 4.2 counter = counter + 1.
	        // 5. requested_bits = Leftmost (no_of_bits_to_return) of temp.
	        // 6. Return SUCCESS and requested_bits.
	        byte[] temp = new byte[(seedLength + 7) / 8];

	        int len = temp.Length / digest.getDigestSize();
	        int counter = 1;

	        byte[] dig = new byte[digest.getDigestSize()];

	        for (int i = 0; i <= len; i++)
	        {
	            digest.Update((byte)counter);

	            digest.Update((byte)(seedLength >> 24));
	            digest.Update((byte)(seedLength >> 16));
	            digest.Update((byte)(seedLength >> 8));
	            digest.Update((byte)seedLength);

	            digest.BlockUpdate(seedMaterial, 0, seedMaterial.Length);

	            digest.DoFinal(dig, 0);

	            int bytesToCopy = ((temp.Length - i * dig.Length) > dig.Length)
	                    ? dig.Length
	                    : (temp.Length - i * dig.Length);
	            Array.Copy(dig, 0, temp, i * dig.Length, bytesToCopy);

	            counter++;
	        }

	        // do a left shift to get rid of excess bits.
	        if (seedLength % 8 != 0)
	        {
	            int shift = 8 - (seedLength % 8);
	            int carry = 0;

	            for (int i = 0; i != temp.Length; i++)
	            {
	                uint b = temp[i] & 0xff;
	                temp[i] = (byte)((b >> shift) | (carry << (8 - shift)));
	                carry = b;
	            }
	        }

	        return temp;
	    }

	    internal static boolean isTooLarge(byte[] bytes, int maxBytes)
	    {
	        return bytes != null && bytes.Length > maxBytes;
	    }
	}
}
