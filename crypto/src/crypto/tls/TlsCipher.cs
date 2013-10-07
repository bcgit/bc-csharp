using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
	public interface TlsCipher
	{
        /// <exception cref="IOException"></exception>
        int GetPlaintextLimit(int ciphertextLimit);

		/// <exception cref="IOException"></exception>
		byte[] EncodePlaintext(long seqNo, ContentType type, byte[] plaintext, int offset, int len, int outputOffset);

		/// <exception cref="IOException"></exception>
		byte[] DecodeCiphertext(long seqNo, ContentType type, byte[] ciphertext, int offset, int len);    

	}
}
