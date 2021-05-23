using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Fpe
{
/**
 * Base class for format-preserving encryption.
 */
public abstract class FpeEngine
{
    protected IBlockCipher baseCipher;

    protected bool forEncryption;
    protected FpeParameters fpeParameters;

    protected FpeEngine(IBlockCipher baseCipher)
    {
        this.baseCipher = baseCipher;
    }

    /// <summary>
    /// Process length bytes from inBuf, writing the output to outBuf.
    /// </summary>
    /// <returns>number of bytes output.</returns>
    /// <param name="inBuf">input data.</param>  
    /// <param name="inOff">offset in input data to start at.</param>  
    /// <param name="length">number of bytes to process.</param>  
    /// <param name="outBuf">destination buffer.</param>  
    /// <param name="outOff">offset to start writing at in destination buffer.</param>  
    public int ProcessBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
    {
        if (fpeParameters == null)
        {
            throw new InvalidOperationException("FPE engine not initialized");
        }

        if (length < 0)
        {
            throw new ArgumentException("input length cannot be negative");
        }

        if (inBuf == null || outBuf == null)
        {
            throw new NullReferenceException("buffer value is null");
        }

        if (inBuf.Length < inOff + length)
        {
            throw new DataLengthException("input buffer too short");
        }

        if (outBuf.Length < outOff + length)
        {
            throw new OutputLengthException("output buffer too short");
        }

        if (forEncryption)
        {
            return encryptBlock(inBuf, inOff, length, outBuf, outOff);
        }
        else
        {
            return decryptBlock(inBuf, inOff, length, outBuf, outOff);
        }
    }

    protected static ushort[] toShortArray(byte[] buf)
    {
        if ((buf.Length & 1) != 0)
        {
            throw new ArgumentException("data must be an even number of bytes for a wide radix");
        }

        ushort[] rv = new ushort[buf.Length / 2];

        for (int i = 0; i != rv.Length; i++)
        {
            rv[i] = Pack.BE_To_UInt16(buf, i * 2);
        }

        return rv;
    }

    protected static bool IsOverrideSet(string propName)
    {
        string propValue = Platform.GetEnvironmentVariable(propName);

        return propValue == null || Platform.EqualsIgnoreCase("true", propValue);
    }

    protected static byte[] toByteArray(ushort[] buf)
    {
        byte[] rv = new byte[buf.Length * 2];

        for (int i = 0; i != buf.Length; i++)
        {
            Pack.UInt16_To_BE(buf[i], rv, i * 2);
        }

        return rv;
    }

    /// <summary>
    /// Initialize the FPE engine for encryption/decryption.
    /// </summary>
    /// <returns>number of bytes output.</returns>
    /// <param name="forEncryption">true if initialising for encryption, false otherwise.</param>  
    /// <param name="parameters ">the key and other parameters to use to set the engine up.</param>  
    public abstract void Init(bool forEncryption, ICipherParameters parameters);

    protected abstract int encryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff);

    protected abstract int decryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff);
}
}
