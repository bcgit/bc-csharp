using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Fpe;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Tests
{
    [TestFixture]
	public class SP80038GTest
	    : SimpleTest
{
    private class FFSample
    {
        private readonly int radix;
        private readonly byte[] key;
        private readonly byte[] plaintext;
        private readonly byte[] ciphertext;
        private readonly byte[] tweak;

        public static FFSample From(int radix, string hexKey, string asciiPT, string asciiCT, string hexTweak)
        {
            return new FFSample(radix, FromHex(hexKey), FromAscii(radix, asciiPT), FromAscii(radix, asciiCT),
                FromHex(hexTweak));
        }

        private static byte FromAlphaNumeric(char c)
        {
            if (c >= '0' && c <= '9')
            {
                return (byte)(c - '0');
            }
            else if (c >= 'a' && c <= 'z')
            {
                return (byte)(10 + (c - 'a'));
            }
            else if (c >= 'A' && c <= 'Z')
            {
                return (byte)(36 + (c - 'A'));
            }
            else
            {
                throw new ArgumentException();
            }
        }

        private static byte[] FromAscii(int radix, string ascii)
        {
            byte[] result = new byte[ascii.Length];
            for (int i = 0; i < result.Length; ++i)
            {
                result[i] = FromAlphaNumeric(ascii[i]);
                if (result[i] < 0 || result[i] >= radix)
                {
                    throw new ArgumentException();
                }
            }
            return result;
        }

        private static byte[] FromHex(string hex)
        {
            return Hex.Decode(hex);
        }

        private FFSample(int radix, byte[] key, byte[] plaintext, byte[] ciphertext, byte[] tweak)
        {
            this.radix = radix;
            this.key = key;
            this.plaintext = plaintext;
            this.ciphertext = ciphertext;
            this.tweak = tweak;
        }

        public byte[] getCiphertext()
        {
            return ciphertext;
        }

        public byte[] getKey()
        {
            return key;
        }

        public byte[] getPlaintext()
        {
            return plaintext;
        }

        public int getRadix()
        {
            return radix;
        }

        public byte[] getTweak()
        {
            return tweak;
        }
    }

    private static FFSample[] ff1Samples = new FFSample[]
        {
            // FF1-AES128
            FFSample.From(10, "2B7E151628AED2A6ABF7158809CF4F3C", "0123456789", "2433477484", ""),
            FFSample.From(10, "2B7E151628AED2A6ABF7158809CF4F3C", "0123456789", "6124200773", "39383736353433323130"),
            FFSample.From(36, "2B7E151628AED2A6ABF7158809CF4F3C", "0123456789abcdefghi", "a9tv40mll9kdu509eum", "3737373770717273373737"),

            // FF1-AES192
            FFSample.From(10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "0123456789", "2830668132", ""),
            FFSample.From(10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "0123456789", "2496655549", "39383736353433323130"),
            FFSample.From(36, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F", "0123456789abcdefghi", "xbj3kv35jrawxv32ysr", "3737373770717273373737"),

            // FF1-AES256
            FFSample.From(10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "0123456789", "6657667009", ""),
            FFSample.From(10, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "0123456789", "1001623463", "39383736353433323130"),
            FFSample.From(36, "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94", "0123456789abcdefghi", "xs8a0azh2avyalyzuwd", "3737373770717273373737"),
        };

    private static FFSample[] ff3_1Samples = new FFSample[]
        {
            // FF3-AES128
            FFSample.From(62, "7793833CE891B496381BD5B882F77EA1", "YbpT3hDo0J9xwCQ5qUWt93iv", "dDEYxViK56lGbV1WdZTPTe4w", "C58797C2580174"),
        };

    private void testFF1()
    {
        for (int i = 0; i < ff1Samples.Length; ++i)
        {
            testFF1Sample(ff1Samples[i]);
        }

        byte[] key = Hex.Decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");
        byte[] plainText = Hex.Decode("0327035100210215");
        byte[] tweak = Hex.Decode("39383736353433323130");

        FpeEngine fpeEngine = new FpeFf1Engine();

        fpeEngine.Init(true, new FpeParameters(new KeyParameter(key), 24, tweak));

        try
        {
            fpeEngine.ProcessBlock(plainText, 0, plainText.Length, plainText, 0);
            Fail("no exception");
        }
        catch (ArgumentException e)
        {
            IsEquals("input data outside of radix", e.Message);
        }

        try
        {
            fpeEngine.ProcessBlock(new byte[] { 1 }, 0, 1, plainText, 0);
            Fail("no exception");
        }
        catch (ArgumentException e)
        {
            IsEquals("input too short", e.Message);
        }
    }

    public void testFF1w()
    {
        byte[] key = Hex.Decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");
        byte[] plainText = Hex.Decode("0327035100210215");
        byte[] cipherText = Hex.Decode("022701f80217020a");
        byte[] tweak = Hex.Decode("39383736353433323130");

        FpeEngine fpeEngine = new FpeFf1Engine();

        fpeEngine.Init(true, new FpeParameters(new KeyParameter(key), 1024, tweak));

        byte[] enc = new byte[plainText.Length];

        fpeEngine.ProcessBlock(plainText, 0, plainText.Length, enc, 0);

        AreEqual(cipherText, enc);

        fpeEngine.Init(false, new FpeParameters(new KeyParameter(key), 1024, tweak));

        fpeEngine.ProcessBlock(cipherText, 0, cipherText.Length, enc, 0);

        AreEqual(plainText, enc);

        byte[] outPt = Hex.Decode("03270F5100210215");

        try
        {
            fpeEngine.ProcessBlock(outPt, 0, outPt.Length, enc, 0);
        }
        catch (ArgumentException e)
        {
            IsEquals("input data outside of radix", e.Message);
        }
    }

    public void testFF3_1()
    {
        for (int i = 0; i < ff3_1Samples.Length; ++i)
        {
            testFF3_1Sample(ff3_1Samples[i]);
        }

        byte[] key = Hex.Decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");
        byte[] plainText = Hex.Decode("0327035100210215");
        byte[] tweak = Hex.Decode("39383736353433");

        FpeEngine fpeEngine = new FpeFf3_1Engine();

        fpeEngine.Init(true, new FpeParameters(new KeyParameter(key), 24, tweak));

        try
        {
            fpeEngine.ProcessBlock(plainText, 0, plainText.Length, plainText, 0);
            Fail("no exception");
        }
        catch (ArgumentException e)
        {
            IsEquals("input data outside of radix", e.Message);
        }

        try
        {
            fpeEngine.Init(true, new FpeParameters(new KeyParameter(key), 24, Hex.Decode("beef")));

            Fail("no exception");
        }
        catch (ArgumentException e)
        {
            IsEquals("tweak should be 56 bits", e.Message);
        }
    }

    private void testFF3_1w()
    {
        byte[] key = Hex.Decode("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6");
        byte[] plainText = Hex.Decode("0327035100210215");
        byte[] cipherText = Hex.Decode("02fb024900310220");
        byte[] tweak = Hex.Decode("39383736353433");

        FpeEngine fpeEngine = new FpeFf3_1Engine();

        fpeEngine.Init(true, new FpeParameters(new KeyParameter(key), 1024, tweak));

        byte[] enc = new byte[plainText.Length];

        fpeEngine.ProcessBlock(plainText, 0, plainText.Length, enc, 0);

        IsTrue("enc failed: " + Hex.ToHexString(enc), AreEqual(cipherText, enc));

        fpeEngine.Init(false, new FpeParameters(new KeyParameter(key), 1024, tweak));

        fpeEngine.ProcessBlock(cipherText, 0, cipherText.Length, enc, 0);

        IsTrue(AreEqual(plainText, enc));

        byte[] outPt = Hex.Decode("03270F5100210215");

        try
        {
            fpeEngine.ProcessBlock(outPt, 0, outPt.Length, enc, 0);
        }
        catch (ArgumentException e)
        {
            IsEquals("input data outside of radix", e.Message);
        }
    }

    private void testDisable()
    {
#if PORTABLE && !DOTNET
        // Can't SetEnvironmentVariable !
#else
        Environment.SetEnvironmentVariable("org.bouncycastle.fpe.disable", "true");
        try
        {
            testFF1();
            Fail("no exception");
        }
        catch (InvalidOperationException e)
        {
            IsEquals("FF1 encryption disabled", e.Message);
        }

        try
        {
            testFF3_1();
            Fail("no exception");
        }
        catch (InvalidOperationException e)
        {
            IsEquals("Fpe disabled", e.Message);
        }
        Environment.SetEnvironmentVariable("org.bouncycastle.fpe.disable", "false");

        Environment.SetEnvironmentVariable("org.bouncycastle.fpe.disable_ff1", "true");
        try
        {
            testFF1();
            Fail("no exception");
        }
        catch (InvalidOperationException e)
        {
            IsEquals("FF1 encryption disabled", e.Message);
        }

        testFF3_1();
        Environment.SetEnvironmentVariable("org.bouncycastle.fpe.disable_ff1", "false");
#endif
    }

    private void testFF3_1_255()
    {
        byte[] key = Hex.Decode("339BB5B1F2D44BAABF87CA1B7380CDC8");
        byte[] tweak = Hex.Decode("3F096DE35BFA31");
        int radix = 256;

        FpeEngine fpeEngine = new FpeFf3_1Engine();

        fpeEngine.Init(true, new FpeParameters(new KeyParameter(key), radix, tweak));

        byte[] bytes = Hex.Decode("31009155FF");
        byte[] enc = new byte[bytes.Length];
        //Encrypt

        fpeEngine.ProcessBlock(bytes, 0, bytes.Length, enc, 0);

        IsTrue(Arrays.AreEqual(Hex.Decode("18fa139dc978a681"), enc));

        //Decrypt
        fpeEngine.Init(false, new FpeParameters(new KeyParameter(key), radix, tweak));

        fpeEngine.ProcessBlock(enc, 0, enc.Length, enc, 0);

        IsTrue(Arrays.AreEqual(bytes, enc));
    }

    private void testFF1Sample(FFSample ff1)
    {
        FpeEngine fpeEngine = new FpeFf1Engine();

        fpeEngine.Init(true, new FpeParameters(new KeyParameter(ff1.getKey()), ff1.getRadix(), ff1.getTweak()));

        byte[] plain = ff1.getPlaintext();
        byte[] enc = new byte[plain.Length];

        fpeEngine.ProcessBlock(plain, 0, plain.Length, enc, 0);

        IsTrue(AreEqual(ff1.getCiphertext(), enc));

        fpeEngine.Init(false, new FpeParameters(new KeyParameter(ff1.getKey()), ff1.getRadix(), ff1.getTweak()));

        fpeEngine.ProcessBlock(ff1.getCiphertext(), 0, ff1.getCiphertext().Length, enc, 0);

        IsTrue(AreEqual(ff1.getPlaintext(), enc));
    }

    private void testFF3_1Sample(FFSample ff3_1)
    {
        FpeEngine fpeEngine = new FpeFf3_1Engine();

        fpeEngine.Init(true, new FpeParameters(new KeyParameter(ff3_1.getKey()), ff3_1.getRadix(), ff3_1.getTweak()));

        byte[] plain = ff3_1.getPlaintext();
        byte[] enc = new byte[plain.Length];

        fpeEngine.ProcessBlock(plain, 0, plain.Length, enc, 0);

        IsTrue(AreEqual(ff3_1.getCiphertext(), enc));

        fpeEngine.Init(false, new FpeParameters(new KeyParameter(ff3_1.getKey()), ff3_1.getRadix(), ff3_1.getTweak()));

        fpeEngine.ProcessBlock(ff3_1.getCiphertext(), 0, plain.Length, enc, 0);

        IsTrue(AreEqual(ff3_1.getPlaintext(), enc));
    }

    public void testFF1Bounds()
    {
        byte[] key = Hex.Decode("339BB5B1F2D44BAABF87CA1B7380CDC8");
        byte[] tweak = Hex.Decode("3F096DE35BFA31");

        FpeEngine fpeEngine = new FpeFf1Engine();

        try
        {
            IAlphabetMapper alphabetMapper = new BasicAlphabetMapper("ABCDEFGHI");

            fpeEngine.Init(true, new FpeParameters(new KeyParameter(key),
                        alphabetMapper.Radix, tweak));

            process(fpeEngine, new byte[] { 1, 2, 3 });
            Fail("no exception");
        }
        catch (ArgumentException e)
        {
           IsEquals("input too short", e.Message);
        }

        try
        {
            IAlphabetMapper alphabetMapper = new BasicAlphabetMapper("ABCD");

            fpeEngine.Init(true, new FpeParameters(new KeyParameter(key),
                        alphabetMapper.Radix, tweak));

            process(fpeEngine, new byte[] { 1, 2, 3 });
            Fail("no exception");
        }
        catch (ArgumentException e)
        {
            IsEquals("input too short", e.Message);
        }
    }

    private void testFF3_1Bounds()
    {
        string bigAlpha = "+-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";

        IAlphabetMapper alphabetMapper = new BasicAlphabetMapper(bigAlpha);

        ff3_1Test(alphabetMapper, "467094C27E47978FE616F475215BF4F1", "ECC8AA7B87B41C", "9RwG+t8cKfa9JweBYgHAA6fHUShNZ5tc", "-DXMBhb3AFPq5Xf4oUva4WbB8eagGK2u");
        ff3_1Test(alphabetMapper, "4DB04B58E97819015A08BA7A39A79C303968A34DB0936FAD", "26B3A632FAADFE", "k5Kop6xYpT0skr1zHHPEt5rPWQ4s4O-3", "JyWzuPL6SNsciOXdEgwnKZJxHiKaTu4Z");
        ff3_1Test(alphabetMapper, "15567AA6CD8CCA401ADB6A10730655AEEC10E9101FD3969A", "379B9572B687A6", "ZpztPp90Oo5ekoNRzqArsAqAbnmM--W6", "NPxEDufvnYzVX3jxupv+iJOuPVpWRPjD");
        try
        {
            ff3_1Test(alphabetMapper, "15567AA6CD8CCA401ADB6A10730655AEEC10E9101FD3969A", "379B9572B687A6", "ZpztPp90Oo5ekoNRzqArsAqAbnmM+-W6ZZ", "L1yx-4YLQG9W1P5yTI7Wp2h0IDcRoBq1kk");
            Fail("no exception 1");
        }
        catch (ArgumentException e)
        {
           IsEquals("maximum input length is 32", e.Message);
        }

        try
        {
            ff3_1Test(alphabetMapper, "15567AA6CD8CCA401ADB6A10730655AEEC10E9101FD3969A", "379B9572B687A6", "Z", "L");
            Fail("no exception 2");
        }
        catch (ArgumentException e)
        {
           IsEquals("input too short", e.Message);
        }

        try
        {
            alphabetMapper = new BasicAlphabetMapper("ABCDEFGHI");

            ff3_1Test(alphabetMapper, "15567AA6CD8CCA401ADB6A10730655AEEC10E9101FD3969A", "379B9572B687A6", "AB", "ZZ");
            Fail("no exception 3");
        }
        catch (ArgumentException e)
        {
           IsEquals("input too short", e.Message);
        }
    }

    private void ff3_1Test(IAlphabetMapper alphabetMapper, string skey, string stweak, string input, string output)
    {
        FpeEngine fpeEncEngine = new FpeFf3_1Engine();
        FpeEngine fpeDecEngine = new FpeFf3_1Engine();

        byte[] key = Hex.Decode(skey);
        byte[] tweak = Hex.Decode(stweak);
        int radix = alphabetMapper.Radix;

        fpeEncEngine.Init(true, new FpeParameters(new KeyParameter(key), radix, tweak));
        fpeDecEngine.Init(false, new FpeParameters(new KeyParameter(key), radix, tweak));

        byte[] bytes = alphabetMapper.ConvertToIndexes(input.ToCharArray());

        byte[] encryptedBytes = process(fpeEncEngine, bytes);
        IsEquals(output, new string(alphabetMapper.ConvertToChars(encryptedBytes)));

        byte[] decryptedBytes = process(fpeDecEngine, encryptedBytes);
        IsTrue(Arrays.AreEqual(bytes, decryptedBytes));
        char[] chars = alphabetMapper.ConvertToChars(decryptedBytes);
        IsEquals(input, new string(chars));
    }

    private byte[] process(FpeEngine fpeEngine, byte[] bytes)
    {
        byte[] rv = new byte[bytes.Length];

        fpeEngine.ProcessBlock(bytes, 0, bytes.Length, rv, 0);

        return rv;
    }

    public void testUtility()
    {
        FpeCharEncryptor fpeEnc = new FpeCharEncryptor(new FpeFf1Engine(), Hex.Decode("2B7E151628AED2A6ABF7158809CF4F3C"), "0123456789".ToCharArray());

        char[] input = "01234567890123456".ToCharArray();
        char[] encrypted = fpeEnc.Process(input);

        FpeCharDecryptor fpeDec = new FpeCharDecryptor(new FpeFf1Engine(), Hex.Decode("2B7E151628AED2A6ABF7158809CF4F3C"), "0123456789".ToCharArray());
        char[] decrypted = fpeDec.Process(encrypted);

        IsTrue("no match", Arrays.AreEqual(input, decrypted));
    }

    public override string Name
    {
        get { return "SP80038GTest"; }
    }

    public override void PerformTest()
    {
        testFF1();
        testFF1w();
        testFF1Bounds();
        testFF3_1();
        testFF3_1w();
        testFF3_1_255();
        testFF3_1Bounds();
        testDisable();
        testUtility();
    }

    public class FpeCharEncryptor
    {
        private readonly FpeEngine fpeEngine;
        private IAlphabetMapper alphabetMapper;

        public FpeCharEncryptor(FpeEngine fpeEngine, byte[] key, char[] alphabet): this(fpeEngine, key, new byte[0], alphabet)
        {

        }

        public FpeCharEncryptor(FpeEngine fpeEngine, byte[] key, byte[] tweak, char[] alphabet)
        {
            this.fpeEngine = fpeEngine;

            alphabetMapper = new BasicAlphabetMapper(alphabet);

            fpeEngine.Init(true, new FpeParameters(new KeyParameter(key), alphabetMapper.Radix, tweak));
        }

        public char[] Process(char[] input)
        {
            byte[] bytes = alphabetMapper.ConvertToIndexes(input);

            fpeEngine.ProcessBlock(bytes, 0, bytes.Length, bytes, 0);

            return alphabetMapper.ConvertToChars(bytes);
        }
    }

    public class FpeCharDecryptor
    {
        private readonly FpeEngine fpeEngine;
        private IAlphabetMapper alphabetMapper;

        public FpeCharDecryptor(FpeEngine fpeEngine, byte[] key, char[] alphabet): this(fpeEngine, key, new byte[0], alphabet)
        {
        }

        public FpeCharDecryptor(FpeEngine fpeEngine, byte[] key, byte[] tweak, char[] alphabet)
        {
            this.fpeEngine = fpeEngine;

            alphabetMapper = new BasicAlphabetMapper(alphabet);

            fpeEngine.Init(false, new FpeParameters(new KeyParameter(key), alphabetMapper.Radix, tweak));
        }

        public char[] Process(char[] input)
        {
            byte[] bytes = alphabetMapper.ConvertToIndexes(input);

            fpeEngine.ProcessBlock(bytes, 0, bytes.Length, bytes, 0);

            return alphabetMapper.ConvertToChars(bytes);
        }
    }
}
}
