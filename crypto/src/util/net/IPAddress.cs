namespace Org.BouncyCastle.Utilities.Net
{
    // TODO[api] Make static
    public class IPAddress
	{
		/**
		 * Validate the given IPv4 or IPv6 address.
		 *
		 * @param address the IP address as a string.
		 *
		 * @return true if a valid address, false otherwise
		 */
		public static bool IsValid(string address)
		{
			return IsValidIPv4(address) || IsValidIPv6(address);
		}

		/**
		 * Validate the given IPv4 or IPv6 address and netmask.
		 *
		 * @param address the IP address as a string.
		 *
		 * @return true if a valid address with netmask, false otherwise
		 */
		public static bool IsValidWithNetMask(string address)
		{
			return IsValidIPv4WithNetmask(address) || IsValidIPv6WithNetmask(address);
		}

		/**
		 * Validate the given IPv4 address.
		 * 
		 * @param address the IP address as a string.
		 *
		 * @return true if a valid IPv4 address, false otherwise
		 */
		public static bool IsValidIPv4(string address)
		{
            int length = address.Length;
            if (length < 7 || length > 15)
                return false;

            int pos = 0;
            for (int octetIndex = 0; octetIndex < 3; ++octetIndex)
            {
				int end = Platform.IndexOf(address, '.', pos);

                if (!IsParseableIPv4Octet(address, pos, end))
                    return false;

                pos = end + 1;
            }

            return IsParseableIPv4Octet(address, pos, length);
		}

		public static bool IsValidIPv4WithNetmask(string address)
		{
			int index = Platform.IndexOf(address, '/');
            if (index < 1)
                return false;

            string before = address.Substring(0, index);
            string after = address.Substring(index + 1);

            return IsValidIPv4(before) && (IsValidIPv4(after) || IsParseableIPv4Mask(after));
		}

		/**
		 * Validate the given IPv6 address.
		 *
		 * @param address the IP address as a string.
		 *
		 * @return true if a valid IPv4 address, false otherwise
		 */
		public static bool IsValidIPv6(string address)
		{
            if (address.Length == 0)
                return false;

            if (address[0] != ':' && GetDigitHexadecimal(address, 0) < 0)
                return false;

            int segmentCount = 0;
            string temp = address + ":";
            bool doubleColonFound = false;

            int pos = 0, end;
            while (pos < temp.Length && (end = Platform.IndexOf(temp, ':', pos)) >= pos)
            {
                if (segmentCount == 8)
                    return false;

                if (pos != end)
                {
                    string value = temp.Substring(pos, end - pos);

                    if (end == temp.Length - 1 && Platform.IndexOf(value, '.') > 0)
                    {
                        // add an extra one as address covers 2 words.
                        if (++segmentCount == 8)
                            return false;

                        if (!IsValidIPv4(value))
                            return false;
                    }
                    else if (!IsParseableIPv6Segment(temp, pos, end))
                    {
                        return false;
                    }
                }
                else
                {
                    if (end != 1 && end != temp.Length - 1 && doubleColonFound)
                        return false;

                    doubleColonFound = true;
                }

                pos = end + 1;
                ++segmentCount;
            }

            return segmentCount == 8 || doubleColonFound;
        }

        public static bool IsValidIPv6WithNetmask(string address)
        {
            int index = Platform.IndexOf(address, '/');
            if (index < 1)
                return false;

            string before = address.Substring(0, index);
            string after = address.Substring(index + 1);

            return IsValidIPv6(before) && (IsValidIPv6(after) || IsParseableIPv6Mask(after));
        }

        private static bool IsParseableIPv4Mask(string s)
        {
            return IsParseableDecimal(s, 0, s.Length, 2, false, 0, 32);
        }

        private static bool IsParseableIPv4Octet(string s, int pos, int end)
        {
            return IsParseableDecimal(s, pos, end, 3, true, 0, 255);
        }

        private static bool IsParseableIPv6Mask(string s)
        {
            return IsParseableDecimal(s, 0, s.Length, 3, false, 1, 128);
        }

        private static bool IsParseableIPv6Segment(string s, int pos, int end)
        {
            return IsParseableHexadecimal(s, pos, end, 4, true, 0x0000, 0xFFFF);
        }

        private static bool IsParseableDecimal(string s, int pos, int end, int maxLength, bool allowLeadingZero,
            int minValue, int maxValue)
        {
            int length = end - pos;
            if (length < 1 | length > maxLength)
                return false;

            bool checkLeadingZero = length > 1 & !allowLeadingZero; 
            if (checkLeadingZero && s[pos] == '0')
                return false;

            int value = 0;
            while (pos < end)
            {
                int d = GetDigitDecimal(s, pos++);
                if (d < 0)
                    return false;

                value *= 10;
                value += d;
            }

            return value >= minValue & value <= maxValue;
        }

        private static bool IsParseableHexadecimal(string s, int pos, int end, int maxLength, bool allowLeadingZero,
            int minValue, int maxValue)
        {
            int length = end - pos;
            if (length < 1 | length > maxLength)
                return false;

            bool checkLeadingZero = length > 1 & !allowLeadingZero;
            if (checkLeadingZero && s[pos] == '0')
                return false;

            int value = 0;
            while (pos < end)
            {
                int d = GetDigitHexadecimal(s, pos++);
                if (d < 0)
                    return false;

                value *= 16;
                value += d;
            }

            return value >= minValue & value <= maxValue;
        }

        private static int GetDigitDecimal(string s, int pos)
        {
            char c = s[pos];
            uint d = (uint)(c - '0');
            return d <= 9 ? (int)d : -1;
        }

        private static int GetDigitHexadecimal(string s, int pos)
        {
            char c = s[pos];
            uint d = (uint)c | 0x20U;
            d -= (d >= (uint)'a') ? ((uint)'a' - 10) : (uint)'0';
            return d <= 16 ? (int)d : -1;
        }
    }
}
