#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER

using System;
using System.Buffers;
using System.Security.Cryptography;

namespace Org.BouncyCastle.Crypto.Prng
{
    /// <summary>
    /// A better default than <see cref="RandomNumberGenerator.Create()"/>
    /// </summary>
    /// <remarks>
    /// <see cref="RandomNumberGenerator.Create()"/> returns an instance that for backward compatibility has to forward
    /// <see cref="GetBytes(byte[], int, int)"/> and <see cref="GetBytes(Span{byte})"/> calls to
    /// <see cref="GetBytes(byte[])"/>, leading to inefficient copying and use of <see cref="ArrayPool{T}.Shared"/>.
    /// </remarks>
    internal sealed class DefaultRandomNumberGenerator
        : RandomNumberGenerator
    {
        // NOTE: Use instances rather than a singleton - to avoid problems around IDisposable
        internal DefaultRandomNumberGenerator()
        {
        }

        public override void GetBytes(byte[] data) => Fill(data.AsSpan());

        public override void GetBytes(byte[] data, int offset, int count) => Fill(data.AsSpan(offset, count));

        public override void GetBytes(Span<byte> data) => Fill(data);

        public override void GetNonZeroBytes(byte[] data) => throw new NotImplementedException();

        public override void GetNonZeroBytes(Span<byte> data) => throw new NotImplementedException();
    }
}

#endif
