using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Numerics;

namespace china_ip_list
{
    class Program
    {
        private static readonly BigInteger IPv6Max = (BigInteger.One << 128) - BigInteger.One;

        public static string chn_ip = "", chnroute = "", chn_ip_v6 = "", chnroute_v6 = "";
        public static string non_chn_ip = "", non_chnroute = "", non_chn_ip_v6 = "", non_chnroute_v6 = "";

        private sealed class IpRangeV4
        {
            public uint Start { get; set; }
            public uint End { get; set; }
        }

        private sealed class IpRangeV6
        {
            public BigInteger Start { get; set; }
            public BigInteger End { get; set; }
        }

        static void Main(string[] args)
        {
            string apnic_ip = GetResponse("http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest");
            //string apnic_ip = "apnic|IN|ipv4|103.16.104.0|1024|20130205|allocated\napnic|CN|ipv4|103.16.108.0|65536|20130205|allocated\napnic|ID|ipv4|103.16.112.0|1024|20130205|assigned\napnic|BN|ipv4|103.16.120.0|1024|20130206|assigned\napnic|CN|ipv4|103.16.124.0|1024|20130206|allocated\napnic|AU|ipv4|103.16.128.0|1024|20130206|allocated\napnic|ID|ipv4|103.16.132.0|512|20130206|assigned\n";
            string[] ip_list = apnic_ip.Split(new string[] { "\n" }, StringSplitOptions.None);

            List<IpRangeV4> cnRangesV4 = new List<IpRangeV4>();
            List<IpRangeV6> cnRangesV6 = new List<IpRangeV6>();

            int i = 1;
            int i_ip6 = 1;
            string save_txt_path = AppContext.BaseDirectory;

            foreach (string per_ip in ip_list)
            {
                //处理IPV4部分
                if (per_ip.Contains("CN|ipv4|"))
                {
                    string[] ip_information = per_ip.Split('|');
                    string ip = ip_information[3];
                    uint ipStart = IpToInt(ip);
                    uint ipCount = Convert.ToUInt32(ip_information[4]);
                    string ip_mask = Convert.ToString(32 - (Math.Log(ipCount) / Math.Log(2)));
                    uint ipEnd = ipStart + ipCount - 1;
                    string end_ip = IntToIp(ipEnd);

                    chnroute += ip + "/" + ip_mask + "\n";
                    chn_ip += ip + " " + end_ip + "\n";

                    cnRangesV4.Add(new IpRangeV4
                    {
                        Start = ipStart,
                        End = ipEnd
                    });

                    i++;
                }

                //处理IPV6部分
                if (per_ip.Contains("CN|ipv6|"))
                {
                    string[] ip_information_v6 = per_ip.Split('|');
                    string ip_v6 = ip_information_v6[3];
                    int prefixLengthV6 = Convert.ToInt32(ip_information_v6[4]);
                    string ip_mask_v6 = Convert.ToString(prefixLengthV6);

                    BigInteger startV6 = IPv6ToBigInteger(ip_v6);
                    BigInteger endV6 = CalculateEndIPv6Address(startV6, prefixLengthV6);
                    string end_ip_v6 = BigIntegerToIPv6(endV6);

                    chnroute_v6 += ip_v6 + "/" + ip_mask_v6 + "\n";
                    chn_ip_v6 += ip_v6 + " " + end_ip_v6 + "\n";

                    cnRangesV6.Add(new IpRangeV6
                    {
                        Start = startV6,
                        End = endV6
                    });

                    i_ip6++;
                }
            }

            List<IpRangeV4> nonCnRangesV4 = GetComplementRangesV4(cnRangesV4);
            List<IpRangeV6> nonCnRangesV6 = GetComplementRangesV6(cnRangesV6);

            foreach (IpRangeV4 rangeV4 in nonCnRangesV4)
            {
                non_chn_ip += IntToIp(rangeV4.Start) + " " + IntToIp(rangeV4.End) + "\n";

                foreach (string cidr in RangeToCidrsV4(rangeV4.Start, rangeV4.End))
                {
                    non_chnroute += cidr + "\n";
                }
            }

            foreach (IpRangeV6 rangeV6 in nonCnRangesV6)
            {
                non_chn_ip_v6 += BigIntegerToIPv6(rangeV6.Start) + " " + BigIntegerToIPv6(rangeV6.End) + "\n";

                foreach (string cidr in RangeToCidrsV6(rangeV6.Start, rangeV6.End))
                {
                    non_chnroute_v6 += cidr + "\n";
                }
            }

            ////Console.Write(chnroute);
            ////Console.Write(chn_ip);
            File.WriteAllText(save_txt_path + "chnroute.txt", chnroute);
            File.WriteAllText(save_txt_path + "chn_ip.txt", chn_ip);
            Console.WriteLine("本次共获取" + i + "条CN IPv4的记录，文件保存于" + save_txt_path + "chn_ip.txt");

            File.WriteAllText(save_txt_path + "chnroute_v6.txt", chnroute_v6);
            File.WriteAllText(save_txt_path + "chn_ip_v6.txt", chn_ip_v6);
            Console.WriteLine("本次共获取" + i_ip6 + "条CN IPv6的记录，文件保存于" + save_txt_path + "chn_ip_v6.txt");

            File.WriteAllText(save_txt_path + "non_chnroute.txt", non_chnroute);
            File.WriteAllText(save_txt_path + "non_chn_ip.txt", non_chn_ip);
            Console.WriteLine("本次共生成" + nonCnRangesV4.Count + "条非CN IPv4范围记录，文件保存于" + save_txt_path + "non_chn_ip.txt");

            File.WriteAllText(save_txt_path + "non_chnroute_v6.txt", non_chnroute_v6);
            File.WriteAllText(save_txt_path + "non_chn_ip_v6.txt", non_chn_ip_v6);
            Console.WriteLine("本次共生成" + nonCnRangesV6.Count + "条非CN IPv6范围记录，文件保存于" + save_txt_path + "non_chn_ip_v6.txt");
        }

        private static string GetResponse(string url)
        {
            if (url.StartsWith("https"))
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
            }
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            HttpResponseMessage response = httpClient.GetAsync(url).Result;
            if (response.IsSuccessStatusCode)
            {
                string result = response.Content.ReadAsStringAsync().Result;
                return result;
            }
            return null;
        }

        private static uint IpToInt(string ipStr)
        {
            string[] ip = ipStr.Split('.');
            uint ipcode = 0xFFFFFF00 | byte.Parse(ip[3]);
            ipcode = ipcode & 0xFFFF00FF | (uint.Parse(ip[2]) << 0x08);
            ipcode = ipcode & 0xFF00FFFF | (uint.Parse(ip[1]) << 0x10);
            ipcode = ipcode & 0x00FFFFFF | (uint.Parse(ip[0]) << 0x18);
            return ipcode;
        }
        private static string IntToIp(uint ipcode)
        {
            byte addr1 = (byte)((ipcode & 0xFF000000) >> 0x18);
            byte addr2 = (byte)((ipcode & 0x00FF0000) >> 0x10);
            byte addr3 = (byte)((ipcode & 0x0000FF00) >> 0x08);
            byte addr4 = (byte)(ipcode & 0x000000FF);
            return string.Format("{0}.{1}.{2}.{3}", addr1, addr2, addr3, addr4);
        }

        private static BigInteger IPv6ToBigInteger(string ipStr)
        {
            byte[] bytes = IPAddress.Parse(ipStr).GetAddressBytes();
            return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }

        private static string BigIntegerToIPv6(BigInteger value)
        {
            if (value < BigInteger.Zero || value > IPv6Max)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "IPv6 数值超出有效范围。\n");
            }

            byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (bytes.Length < 16)
            {
                byte[] padded = new byte[16];
                Buffer.BlockCopy(bytes, 0, padded, 16 - bytes.Length, bytes.Length);
                bytes = padded;
            }

            return new IPAddress(bytes).ToString();
        }

        private static BigInteger CalculateEndIPv6Address(BigInteger startIpAddress, int networkLength)
        {
            int subnetBits = 128 - networkLength;
            return startIpAddress + (BigInteger.One << subnetBits) - BigInteger.One;
        }

        private static List<IpRangeV4> GetComplementRangesV4(List<IpRangeV4> source)
        {
            List<IpRangeV4> merged = source
                .OrderBy(item => item.Start)
                .ThenBy(item => item.End)
                .ToList();

            List<IpRangeV4> normalized = new List<IpRangeV4>();
            foreach (IpRangeV4 item in merged)
            {
                if (normalized.Count == 0)
                {
                    normalized.Add(new IpRangeV4 { Start = item.Start, End = item.End });
                    continue;
                }

                IpRangeV4 last = normalized[normalized.Count - 1];
                if ((ulong)item.Start <= (ulong)last.End + 1)
                {
                    if (item.End > last.End)
                    {
                        last.End = item.End;
                    }
                }
                else
                {
                    normalized.Add(new IpRangeV4 { Start = item.Start, End = item.End });
                }
            }

            List<IpRangeV4> result = new List<IpRangeV4>();
            ulong cursor = 0;

            foreach (IpRangeV4 item in normalized)
            {
                if (cursor < item.Start)
                {
                    result.Add(new IpRangeV4
                    {
                        Start = (uint)cursor,
                        End = item.Start - 1
                    });
                }

                cursor = (ulong)item.End + 1;
            }

            if (cursor <= uint.MaxValue)
            {
                result.Add(new IpRangeV4
                {
                    Start = (uint)cursor,
                    End = uint.MaxValue
                });
            }

            return result;
        }

        private static List<IpRangeV6> GetComplementRangesV6(List<IpRangeV6> source)
        {
            List<IpRangeV6> merged = source
                .OrderBy(item => item.Start)
                .ThenBy(item => item.End)
                .ToList();

            List<IpRangeV6> normalized = new List<IpRangeV6>();
            foreach (IpRangeV6 item in merged)
            {
                if (normalized.Count == 0)
                {
                    normalized.Add(new IpRangeV6 { Start = item.Start, End = item.End });
                    continue;
                }

                IpRangeV6 last = normalized[normalized.Count - 1];
                if (item.Start <= last.End + BigInteger.One)
                {
                    if (item.End > last.End)
                    {
                        last.End = item.End;
                    }
                }
                else
                {
                    normalized.Add(new IpRangeV6 { Start = item.Start, End = item.End });
                }
            }

            List<IpRangeV6> result = new List<IpRangeV6>();
            BigInteger cursor = BigInteger.Zero;

            foreach (IpRangeV6 item in normalized)
            {
                if (cursor < item.Start)
                {
                    result.Add(new IpRangeV6
                    {
                        Start = cursor,
                        End = item.Start - BigInteger.One
                    });
                }

                cursor = item.End + BigInteger.One;
            }

            if (cursor <= IPv6Max)
            {
                result.Add(new IpRangeV6
                {
                    Start = cursor,
                    End = IPv6Max
                });
            }

            return result;
        }

        private static IEnumerable<string> RangeToCidrsV4(uint start, uint end)
        {
            ulong current = start;
            ulong max = end;

            while (current <= max)
            {
                int trailingZeroBits = current == 0 ? 32 : CountTrailingZeroBits((uint)current);
                int prefixByAlignment = 32 - trailingZeroBits;

                ulong remaining = max - current + 1;
                int prefixByRange = 32 - FloorLog2(remaining);

                int prefix = Math.Max(prefixByAlignment, prefixByRange);
                yield return IntToIp((uint)current) + "/" + prefix;

                if (prefix == 0)
                {
                    yield break;
                }

                ulong blockSize = 1UL << (32 - prefix);
                current += blockSize;
            }
        }

        private static IEnumerable<string> RangeToCidrsV6(BigInteger start, BigInteger end)
        {
            BigInteger current = start;
            BigInteger max = end;

            while (current <= max)
            {
                int trailingZeroBits = current.IsZero ? 128 : CountTrailingZeroBits(current, 128);
                int prefixByAlignment = 128 - trailingZeroBits;

                BigInteger remaining = max - current + BigInteger.One;
                int prefixByRange = 128 - FloorLog2(remaining);

                int prefix = Math.Max(prefixByAlignment, prefixByRange);
                yield return BigIntegerToIPv6(current) + "/" + prefix;

                if (prefix == 0)
                {
                    yield break;
                }

                BigInteger blockSize = BigInteger.One << (128 - prefix);
                current += blockSize;
            }
        }

        private static int CountTrailingZeroBits(uint value)
        {
            int count = 0;
            while ((value & 1) == 0)
            {
                count++;
                value >>= 1;
            }
            return count;
        }

        private static int CountTrailingZeroBits(BigInteger value, int maxBits)
        {
            int count = 0;
            while (count < maxBits && (value & BigInteger.One) == BigInteger.Zero)
            {
                count++;
                value >>= 1;
            }
            return count;
        }

        private static int FloorLog2(ulong value)
        {
            int result = 0;
            while (value > 1)
            {
                value >>= 1;
                result++;
            }
            return result;
        }

        private static int FloorLog2(BigInteger value)
        {
            byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
            int bitLength = bytes.Length * 8;

            byte first = bytes[0];
            int leadingZeroCount = 0;
            for (int i = 7; i >= 0; i--)
            {
                if ((first & (1 << i)) == 0)
                {
                    leadingZeroCount++;
                }
                else
                {
                    break;
                }
            }

            return bitLength - leadingZeroCount - 1;
        }


    }
}
