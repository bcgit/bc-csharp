using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Prng.Drbg
{
	internal class DrbgUtilities
	{
		private static readonly IDictionary<string, int> MaxSecurityStrengths =
			new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        static DrbgUtilities()
	    {
			MaxSecurityStrengths.Add("SHA-1", 128);

			MaxSecurityStrengths.Add("SHA-224", 192);
			MaxSecurityStrengths.Add("SHA-256", 256);
			MaxSecurityStrengths.Add("SHA-384", 256);
			MaxSecurityStrengths.Add("SHA-512", 256);

			MaxSecurityStrengths.Add("SHA-512/224", 192);
			MaxSecurityStrengths.Add("SHA-512/256", 256);
	    }

        internal static int GetMaxSecurityStrength(IDigest d)
	    {
	        return MaxSecurityStrengths[d.AlgorithmName];
	    }

        internal static int GetMaxSecurityStrength(IMac m)
	    {
	        string name = m.AlgorithmName;

            return MaxSecurityStrengths[name.Substring(0, name.IndexOf("/"))];
	    }

        /**
	     * Used by both Dual EC and Hash.
	     */
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static void HashDF(IDigest digest, ReadOnlySpan<byte> seedMaterial, int seedLength, Span<byte> output)
#else
		internal static void HashDF(IDigest digest, byte[] seedMaterial, int seedLength, byte[] output)
#endif
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
			int outputLength = (seedLength + 7) / 8;

            int digestSize = digest.GetDigestSize();
            int len = outputLength / digestSize;
	        int counter = 1;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
			Span<byte> dig = digestSize <= 128
				? stackalloc byte[digestSize]
				: new byte[digestSize];
			Span<byte> header = stackalloc byte[5];
            Pack.UInt32_To_BE((uint)seedLength, header[1..]);
#else
			byte[] dig = new byte[digestSize];
			byte[] header = new byte[5];
            Pack.UInt32_To_BE((uint)seedLength, header, 1);
#endif

            for (int i = 0; i <= len; i++, counter++)
	        {
                header[0] = (byte)counter;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                digest.BlockUpdate(header);
                digest.BlockUpdate(seedMaterial);
                digest.DoFinal(dig);

                int bytesToCopy = System.Math.Min(digestSize, outputLength - i * digestSize);
				dig[..bytesToCopy].CopyTo(output[(i * digestSize)..]);
#else
				digest.BlockUpdate(header, 0, header.Length);
				digest.BlockUpdate(seedMaterial, 0, seedMaterial.Length);
                digest.DoFinal(dig, 0);

				int bytesToCopy = System.Math.Min(digestSize, outputLength - i * digestSize);
	            Array.Copy(dig, 0, output, i * digestSize, bytesToCopy);
#endif
            }

            // do a left shift to get rid of excess bits.
            if (seedLength % 8 != 0)
	        {
	            int shift = 8 - (seedLength % 8);
	            uint carry = 0;

                for (int i = 0; i != outputLength; i++)
	            {
	                uint b = output[i];
                    output[i] = (byte)((b >> shift) | (carry << (8 - shift)));
	                carry = b;
	            }
	        }
	    }
	}
}
