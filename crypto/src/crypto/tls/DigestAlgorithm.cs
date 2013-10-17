using System;

namespace Org.BouncyCastle.Crypto.Tls
{
	public enum DigestAlgorithm : int
	{
		/*
		 * Note that the values here are implementation-specific and arbitrary.
		 * It is recommended not to depend on the particular values (e.g. serialization).
		 */
		NULL = 0,
		MD5 = 1,
		SHA = 2,

    /*
     * RFC 5246
     */
		SHA256 = 3,
		SHA384 = 4,
        SHA512 = 5
	}
}
