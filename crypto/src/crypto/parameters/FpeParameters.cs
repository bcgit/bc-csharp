using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
/// <summary>Parameters for format-preserving encryption: a key and a tweak.</summary>
public sealed class FpeParameters
    : ICipherParameters
{
    private readonly KeyParameter key;
    private readonly int radix;
    private readonly byte[] tweak;
    private readonly bool useInverse;

    /// <summary>Create a new <see cref="FpeParameters"/>.</summary>
    /// <param name="key">The key.</param>
    /// <param name="radix">The radix.</param>
    /// <param name="tweak">The tweak.</param>
    public FpeParameters(KeyParameter key, int radix, byte[] tweak): this(key, radix, tweak, false)
    {

    }

    /// <summary>Create a new <see cref="FpeParameters"/>.</summary>
    /// <param name="key">The key.</param>
    /// <param name="radix">The radix.</param>
    /// <param name="tweak">The tweak.</param>
    /// <param name="useInverse">true if use inverse, false otherwise.</param>
    public FpeParameters(KeyParameter key, int radix, byte[] tweak, bool useInverse)
    {
        this.key = key;
        this.radix = radix;
        this.tweak = Arrays.Clone(tweak);
        this.useInverse = useInverse;
    }

    /// <summary>Gets the key.</summary>
    public KeyParameter Key
    {
        get { return key; }
    }

    /// <summary>Gets the radix.</summary>
    public int Radix
    {
        get { return radix; }
    }

    /// <summary>Gets the use inverse function.</summary>
    public bool UseInverseFunction
    {
        get { return useInverse; }
    }

    /// <summary>Return the tweak.</summary>
    public byte[] GetTweak()
    {
        return Arrays.Clone(tweak);
    }
}
}
