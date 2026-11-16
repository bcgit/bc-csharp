using System;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>Interface for generators of streamed OpenPGP data.</summary>
    public interface IStreamGenerator
    {
        /// <summary>Finish writing the data and close the generator.</summary>
        [Obsolete("Dispose any opened Stream directly")]
        void Close();
    }
}
