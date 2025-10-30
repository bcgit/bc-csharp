using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.OpenSsl
{
	internal sealed class PemUtilities
	{
		private enum PemBaseAlg { AES_128, AES_192, AES_256, BF, DES, DES_EDE, DES_EDE3, RC2, RC2_40, RC2_64 };
		private enum PemMode { CBC, CFB, ECB, OFB };

		static PemUtilities()
		{
			// Signal to obfuscation tools not to change enum constants
			Enums.GetArbitraryValue<PemBaseAlg>().ToString();
            Enums.GetArbitraryValue<PemMode>().ToString();
		}

        private static void ParseDekAlgName(string dekAlgName, out PemBaseAlg baseAlg, out PemMode mode)
        {
            if (dekAlgName == "DES-EDE" || dekAlgName == "DES-EDE3")
            {
				if (Enums.TryGetEnumValue<PemBaseAlg>(dekAlgName, out baseAlg))
				{
                    mode = PemMode.ECB;
                    return;
                }
            }
			else
			{
                int pos = dekAlgName.LastIndexOf('-');
                if (pos >= 0)
                {
                    if (Enums.TryGetEnumValue<PemBaseAlg>(dekAlgName.Substring(0, pos), out baseAlg) &&
						Enums.TryGetEnumValue<PemMode>(dekAlgName.Substring(pos + 1), out mode))
					{
						return;
					}
                }
            }

			throw new EncryptionException("Unknown DEK algorithm: " + dekAlgName);
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal static byte[] Crypt(bool encrypt, ReadOnlySpan<byte> bytes, ReadOnlySpan<char> password,
			string dekAlgName, ReadOnlySpan<byte> iv)
        {
            PemBaseAlg baseAlg;
            PemMode mode;
            ParseDekAlgName(dekAlgName, out baseAlg, out mode);

            string padding;
            switch (mode)
            {
            case PemMode.CBC:
            case PemMode.ECB:
                padding = "PKCS5Padding";
                break;
            case PemMode.CFB:
            case PemMode.OFB:
                padding = "NoPadding";
                break;
            default:
                throw new EncryptionException("Unknown DEK algorithm: " + dekAlgName);
            }

            string algorithm;

            ReadOnlySpan<byte> salt = iv;
            switch (baseAlg)
            {
            case PemBaseAlg.AES_128:
            case PemBaseAlg.AES_192:
            case PemBaseAlg.AES_256:
                algorithm = "AES";
                if (salt.Length > 8)
                {
					salt = iv[..8].ToArray();
                }
                break;
            case PemBaseAlg.BF:
                algorithm = "BLOWFISH";
                break;
            case PemBaseAlg.DES:
                algorithm = "DES";
                break;
            case PemBaseAlg.DES_EDE:
            case PemBaseAlg.DES_EDE3:
                algorithm = "DESede";
                break;
            case PemBaseAlg.RC2:
            case PemBaseAlg.RC2_40:
            case PemBaseAlg.RC2_64:
                algorithm = "RC2";
                break;
            default:
                throw new EncryptionException("Unknown DEK algorithm: " + dekAlgName);
            }

            string cipherName = algorithm + "/" + mode + "/" + padding;
            IBufferedCipher cipher = CipherUtilities.GetCipher(cipherName);

            ICipherParameters cParams = GetCipherParameters(password, baseAlg, salt);

            if (mode != PemMode.ECB)
            {
                cParams = new ParametersWithIV(cParams, iv);
            }

            cipher.Init(encrypt, cParams);

			int outputSize = cipher.GetOutputSize(bytes.Length);
			byte[] output = new byte[outputSize];
			int length = cipher.DoFinal(bytes, output);
			if (length < outputSize)
			{
				output = Arrays.CopyOfRange(output, 0, length);
			}
			return output;
        }
#else
		internal static byte[] Crypt(
			bool	encrypt,
			byte[]	bytes,
			char[]	password,
			string	dekAlgName,
			byte[]	iv)
		{
			PemBaseAlg baseAlg;
			PemMode mode;
			ParseDekAlgName(dekAlgName, out baseAlg, out mode);

			string padding;
			switch (mode)
			{
				case PemMode.CBC:
				case PemMode.ECB:
					padding = "PKCS5Padding";
					break;
				case PemMode.CFB:
				case PemMode.OFB:
					padding = "NoPadding";
					break;
				default:
					throw new EncryptionException("Unknown DEK algorithm: " + dekAlgName);
			}

			string algorithm;

			byte[] salt = iv;
			switch (baseAlg)
			{
				case PemBaseAlg.AES_128:
				case PemBaseAlg.AES_192:
				case PemBaseAlg.AES_256:
					algorithm = "AES";
					if (salt.Length > 8)
					{
						salt = new byte[8];
						Array.Copy(iv, 0, salt, 0, salt.Length);
					}
					break;
				case PemBaseAlg.BF:
					algorithm = "BLOWFISH";
					break;
				case PemBaseAlg.DES:
					algorithm = "DES";
					break;
				case PemBaseAlg.DES_EDE:
				case PemBaseAlg.DES_EDE3:
					algorithm = "DESede";
					break;
				case PemBaseAlg.RC2:
				case PemBaseAlg.RC2_40:
				case PemBaseAlg.RC2_64:
					algorithm = "RC2";
					break;
				default:
					throw new EncryptionException("Unknown DEK algorithm: " + dekAlgName);
			}

			string cipherName = algorithm + "/" + mode + "/" + padding;
			IBufferedCipher cipher = CipherUtilities.GetCipher(cipherName);

			ICipherParameters cParams = GetCipherParameters(password, baseAlg, salt);

			if (mode != PemMode.ECB)
			{
				cParams = new ParametersWithIV(cParams, iv);
			}

			cipher.Init(encrypt, cParams);

			return cipher.DoFinal(bytes);
		}
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static ICipherParameters GetCipherParameters(ReadOnlySpan<char> password, PemBaseAlg baseAlg,
            ReadOnlySpan<byte> salt)
#else
        private static ICipherParameters GetCipherParameters(char[] password, PemBaseAlg baseAlg, byte[] salt)
#endif
        {
            if (!TryGetCipherAlgorithm(baseAlg, out var algorithm, out var keyBits))
                return null;

            OpenSslPbeParametersGenerator pGen = new OpenSslPbeParametersGenerator();

            pGen.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(password), salt);

            return pGen.GenerateDerivedParameters(algorithm, keyBits);
        }

        private static bool TryGetCipherAlgorithm(PemBaseAlg baseAlg, out string algorithm, out int keyBits)
        {
            switch (baseAlg)
            {
            case PemBaseAlg.AES_128:
            {
                algorithm = "AES128";
                keyBits = 128;
                break;
            }
            case PemBaseAlg.AES_192:
            {
                algorithm = "AES192";
                keyBits = 192;
                break;
            }
            case PemBaseAlg.AES_256:
            {
                algorithm = "AES256";
                keyBits = 256;
                break;
            }
            case PemBaseAlg.BF:
            {
                algorithm = "BLOWFISH";
                keyBits = 128;
                break;
            }
            case PemBaseAlg.DES:
            {
                algorithm = "DES";
                keyBits = 64;
                break;
            }
            case PemBaseAlg.DES_EDE:
            {
                algorithm = "DESEDE";
                keyBits = 128;
                break;
            }
            case PemBaseAlg.DES_EDE3:
            {
                algorithm = "DESEDE3";
                keyBits = 192;
                break;
            }
            case PemBaseAlg.RC2:
            {
                algorithm = "RC2";
                keyBits = 128;
                break;
            }
            case PemBaseAlg.RC2_40:
            {
                algorithm = "RC2";
                keyBits = 40;
                break;
            }
            case PemBaseAlg.RC2_64:
            {
                algorithm = "RC2";
                keyBits = 64;
                break;
            }
            default:
            {
                algorithm = null;
                keyBits = -1;
                return false;
            }
            }
            return true;
        }
    }
}
