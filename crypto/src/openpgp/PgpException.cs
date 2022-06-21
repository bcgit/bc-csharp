using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>Generic exception class for PGP encoding/decoding problems.</remarks>
#if !PORTABLE
    [Serializable]
#endif
    public class PgpException
		: Exception
	{
		public PgpException() : base() {}
		public PgpException(string message) : base(message) {}
		public PgpException(string message, Exception exception) : base(message, exception) {}
	}
}
