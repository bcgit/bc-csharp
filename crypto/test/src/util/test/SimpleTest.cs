using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace Org.BouncyCastle.Utilities.Test
{
    public abstract class SimpleTest
        : ITest
    {
		public abstract string Name
		{
			get;
		}

		private ITestResult Success()
        {
            return SimpleTestResult.Successful(this, "Okay");
        }

        internal void Fail(
            string message)
        {
            throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }

        internal void Fail(
            string		message,
            Exception	throwable)
        {
            throw new TestFailedException(SimpleTestResult.Failed(this, message, throwable));
        }

		internal void Fail(
            string message,
            object expected,
            object found)
        {
            throw new TestFailedException(SimpleTestResult.Failed(this, message, expected, found));
        }

        internal void IsTrue(bool value)
        {
            if (!value)
                throw new TestFailedException(SimpleTestResult.Failed(this, "no message"));
        }

        internal void IsTrue(string message, bool value)
        {
            if (!value)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }

        internal void IsEquals(object a, object b)
        {
            if (!a.Equals(b))
                throw new TestFailedException(SimpleTestResult.Failed(this, "no message"));
        }

        internal void IsEquals(int a, int b)
        {
            if (a != b)
                throw new TestFailedException(SimpleTestResult.Failed(this, "no message"));
        }

        internal void IsEquals(string message, bool a, bool b)
        {
            if (a != b)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }

        internal void IsEquals(string message, long a, long b)
        {
            if (a != b)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }

        internal void IsEquals(string message, object a, object b)
        {
            if (a == null && b == null)
                return;

            if (a == null)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
            if (b == null)
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
            if (!a.Equals(b))
                throw new TestFailedException(SimpleTestResult.Failed(this, message));
        }

        internal bool AreEqual(byte[] a, byte[] b)
        {
            return Arrays.AreEqual(a, b);
        }

        internal bool AreEqual(byte[] a, int aFromIndex, int aToIndex, byte[] b, int bFromIndex, int bToIndex)
        {
            return Arrays.AreEqual(a, aFromIndex, aToIndex, b, bFromIndex, bToIndex);
        }

		public virtual ITestResult Perform()
        {
            try
            {
                PerformTest();

				return Success();
            }
            catch (TestFailedException e)
            {
                return e.Result;
            }
            catch (Exception e)
            {
                return SimpleTestResult.Failed(this, "Exception: " +  e, e);
            }
        }

		internal static void RunTest(
            ITest test)
        {
            RunTest(test, Console.Out);
        }

		internal static void RunTest(
            ITest		test,
            TextWriter	outStream)
        {
            ITestResult result = test.Perform();

			outStream.WriteLine(result.ToString());
            if (result.GetException() != null)
            {
                outStream.WriteLine(result.GetException().StackTrace);
            }
        }

		internal static Stream GetTestDataAsStream(
			string name)
		{
			string fullName = GetFullName(name);

			return GetAssembly().GetManifestResourceStream(fullName);
		}

		internal static string[] GetTestDataEntries(
			string prefix)
		{
			string fullPrefix = GetFullName(prefix);

			var result = new List<string>();
			string[] fullNames = GetAssembly().GetManifestResourceNames();
			foreach (string fullName in fullNames)
			{
				if (fullName.StartsWith(fullPrefix))
				{
					string name = GetShortName(fullName);
					result.Add(name);
				}
			}
            return result.ToArray();
		}

        private static Assembly GetAssembly()
        {
            return typeof(SimpleTest).Assembly;
        }

        private static string GetFullName(string name)
		{
            return "BouncyCastle.Crypto.Tests.data." + name;
        }

        private static string GetShortName(string fullName)
		{
            return fullName.Substring("BouncyCastle.Crypto.Tests.data.".Length);
		}

		private static string GetNewLine()
		{
			return Environment.NewLine;
		}

		internal static readonly string NewLine = GetNewLine();

		public abstract void PerformTest();

        public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second)
        {
            return new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);
        }

        public static DateTime MakeUtcDateTime(int year, int month, int day, int hour, int minute, int second, int millisecond)
        {
            return new DateTime(year, month, day, hour, minute, second, millisecond, DateTimeKind.Utc);
        }

        public static void TestBitStringConstant(int bitNo, int value)
        {
            int expectedValue = 1 << ((bitNo | 7) - (bitNo & 7));
            if (expectedValue != value)
                throw new ArgumentException("bit value " + bitNo + " wrong");
        }
    }
}
