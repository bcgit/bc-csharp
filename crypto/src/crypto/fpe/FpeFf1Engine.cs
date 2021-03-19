using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Fpe
{
public class FpeFf1Engine
    : FpeEngine
{
    public FpeFf1Engine(): this(new AesEngine())
    {
    }

    public FpeFf1Engine(IBlockCipher baseCipher): base(baseCipher)
    {
        if (IsOverrideSet(SP80038G.FPE_DISABLED)
            || IsOverrideSet(SP80038G.FF1_DISABLED))
        {
            throw new InvalidOperationException("FF1 encryption disabled");
        }
    }

    public override void Init(bool forEncryption, ICipherParameters parameters)
    {
        this.forEncryption = forEncryption;

        this.fpeParameters = (FpeParameters)parameters;

        baseCipher.Init(!fpeParameters.UseInverseFunction, fpeParameters.Key);
    }

    protected override int encryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
    {
        byte[] enc;

        if (fpeParameters.Radix > 256)
        {
            enc = toByteArray(SP80038G.EncryptFF1w(baseCipher, fpeParameters.Radix, fpeParameters.GetTweak(), toShortArray(inBuf), inOff, length / 2));
        }
        else
        {
            enc = SP80038G.EncryptFF1(baseCipher, fpeParameters.Radix, fpeParameters.GetTweak(), inBuf, inOff, length);
        }

        Array.Copy(enc, 0, outBuf, outOff, length);

        return length;
    }

    protected override int decryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
    {
        byte[] dec;

        if (fpeParameters.Radix > 256)
        {
            dec = toByteArray(SP80038G.DecryptFF1w(baseCipher, fpeParameters.Radix, fpeParameters.GetTweak(), toShortArray(inBuf), inOff, length / 2));
        }
        else
        {
            dec = SP80038G.DecryptFF1(baseCipher, fpeParameters.Radix, fpeParameters.GetTweak(), inBuf, inOff, length);
        }

        Array.Copy(dec, 0, outBuf, outOff, length);

        return length;
    }
}
}
