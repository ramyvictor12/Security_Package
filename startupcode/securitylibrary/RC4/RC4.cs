using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        static string HexStringToString(string plainText)
        {
            plainText += '1';
            string res = "", prefix = "";

            int n = plainText.Length;
            for (int i = 2; i < n; i++)
            {
                if (i % 2 == 0 && res.Length == 2)
                {
                    int num1 = 0, num2 = 0;
                    //num less than 10
                    if (res[0] >= '0' && res[0] <= '9')

                    {
                        num1 = res[0] - '0';
                    }
                    //char 
                    else if (res[0] >= 'a' && res[0] <= 'f')
                        num1 = res[0] - 'a' + 10;

                    if (res[1] >= '0' && res[1] <= '9')
                        num2 = res[1] - '0';

                    else if (res[1] >= 'a' && res[1] <= 'f')
                        num2 = res[1] - 'a' + 10;


                    prefix += (char)((16 * num1) + num2);
                    res = "";
                }
                res += plainText[i];
            }
            return prefix;
        }
        //public static string HexStringToString(string hexString)
        //{

        //    hexString = hexString.Substring(2, hexString.Length - 2);
        //    byte[] byteArray = new byte[hexString.Length / 2];

        //    for (int i = 0; i < byteArray.Length; i++)
        //        byteArray[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);

        //    return Encoding.ASCII.GetString(byteArray);
        //}

        public static void Swap<T>(ref T num1, ref T num2)
        {
            T tmp = num1;
            num1 = num2;
            num2 = tmp;
        }
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
        return Encrypt(cipherText, key);
        }

        public override  string Encrypt(string plainText, string key)
        {
            bool hex = false;
            if (plainText[0] == '0' && plainText[1] == 'x')
            {
                hex = true;
                plainText = HexStringToString(plainText);
                key = HexStringToString(key);
            }
            int[] S = new int[256];
            string T = "";
            for (int i = 0; i < 256; i++)

            {
                S[i] = i;
                T += key[i % key.Length];
            }


            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                Swap<int>(ref S[i], ref S[j]);
            }
            int l = j = 0, t, k, counter = 0;
            string cipherText = "";
            while (counter < plainText.Length)
            {
                l = (l + 1) % 256;
                j = (j + S[l]) % 256;
                Swap<int>(ref S[l], ref S[j]);
                t = (S[l] + S[j]) % 256;
                k = S[t];
                char c = (char)(plainText[counter] ^ k);
                cipherText += c;
                counter++;
            }

            if (hex)
            {
                string ans = "";

                for (int i = 0; i < cipherText.Length; i++)
                {
                    int x = cipherText[i];
                    int sum = x / 16;
                    int carry = x % 16;

                    if (sum >= 0 && carry <= 9)
                        sum += '0';
                    if (sum >= 10 && sum <= 15)
                        sum = 'a' + (sum - 10);
                    if (carry >= 0 && carry <= 9)
                        carry += '0';
                    if (carry >= 10 && carry <= 15)
                        carry = 'a' + (carry - 10);


                    ans += (char)sum;
                    ans += (char)carry;
                }
                return "0x"+ans;
            }

            return cipherText;
        }
    }
}
