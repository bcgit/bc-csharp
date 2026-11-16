using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Constants describing the layout of TLS and DTLS records.</summary>
    public abstract class RecordFormat
    {
        /// <summary>The <c>TypeOffset</c> constant, with the value <c>0</c>.</summary>
        public const int TypeOffset = 0;
        /// <summary>The <c>VersionOffset</c> constant, with the value <c>1</c>.</summary>
        public const int VersionOffset = 1;
        /// <summary>The <c>LengthOffset</c> constant, with the value <c>3</c>.</summary>
        public const int LengthOffset = 3;
        /// <summary>The <c>FragmentOffset</c> constant, with the value <c>5</c>.</summary>
        public const int FragmentOffset = 5;
    }
}
