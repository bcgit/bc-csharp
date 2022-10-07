using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.Encoders
{
	/**
	 * Encode and decode byte arrays (typically from binary to 7-bit ASCII
	 * encodings).
	 */
	public interface IEncoder
	{
		int Encode(byte[] data, int off, int length, Stream outStream);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
		int Encode(ReadOnlySpan<byte> data, Stream outStream);
#endif

		int Decode(byte[] data, int off, int length, Stream outStream);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
		int Decode(ReadOnlySpan<byte> data, Stream outStream);
#endif

		int DecodeString(string data, Stream outStream);
	}
}
