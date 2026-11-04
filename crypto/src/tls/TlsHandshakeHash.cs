using System;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Base interface for an object that can calculate a handshake hash.</summary>
    public interface TlsHandshakeHash
        : TlsHash
    {
        /// <exception cref="IOException"/>
        void CopyBufferTo(Stream output);

        /// <summary>Force the hash to buffer the handshake messages, so they are available later.</summary>
        void ForceBuffering();

        /// <summary>Notify the hash that the PRF has been determined.</summary>
        void NotifyPrfDetermined();

        /// <summary>Start tracking a hash algorithm.</summary>
        /// <param name="cryptoHashAlgorithm">The crypto hash algorithm.</param>
        void TrackHashAlgorithm(int cryptoHashAlgorithm);

        /// <summary>Stop accepting further hash algorithms to be tracked.</summary>
        void SealHashAlgorithms();

        /// <summary>Stop tracking the handshake messages.</summary>
        void StopTracking();

        /// <summary>Fork the hash that is used for the PRF.</summary>
        /// <returns>A copy of the PRF hash in its current state.</returns>
        TlsHash ForkPrfHash();

        /// <summary>Calculate the final hash for an algorithm.</summary>
        /// <param name="cryptoHashAlgorithm">The crypto hash algorithm.</param>
        /// <returns>The hash value.</returns>
        byte[] GetFinalHash(int cryptoHashAlgorithm);
    }
}
