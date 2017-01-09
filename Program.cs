using System;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Azure.KeyVault.Models;
using System.Security.Cryptography.X509Certificates;

namespace ConsoleApp
{
    class Program
    {
        static string aadClientID = "5dab0f90-d007-4918-97bd-7b804d3780ce";
        static string aadClientSecret = "Oy1hrSvsKGlYS83dxGwSo/hlB6OGZHA66HMJVHcsmgI=";
        static string keyVaultUrl = "https://dmac.vault.azure.net/secrets/";
        static string certThumbPrint = "624B114E323B3BC87AE77A0D376FF3BA57E97087";
        static ClientAssertionCertificate AssertionCert { get; set; }

        static void Main(string[] args)
        {
            RunSample().GetAwaiter().GetResult();
            Console.ReadLine(); 
        }

        static async Task RunSample()
        {
            Console.WriteLine("Access KeyVault using AAD Client Secret...");
            var kvClient1 = new KeyVaultClient(GetAccessToken);
            printSecret(await kvClient1.GetSecretAsync(keyVaultUrl + "secretPassword"));
            printSecret(await kvClient1.GetSecretAsync(keyVaultUrl + "favourite-color/7fc2ec641ccb4daf87759ea77bf2b1fd"));
            printSecret(await kvClient1.GetSecretAsync(keyVaultUrl + "favourite-color"));
            Console.WriteLine();

            Console.WriteLine("Access KeyVault using AAD Certificate...");
            GetAssertionCert();
            var kvClient2 = new KeyVaultClient(GetAccessTokenViaCert);
            printSecret(await kvClient2.GetSecretAsync(keyVaultUrl + "secretPassword"));
            printSecret(await kvClient2.GetSecretAsync(keyVaultUrl + "favourite-color/7fc2ec641ccb4daf87759ea77bf2b1fd"));
            printSecret(await kvClient2.GetSecretAsync(keyVaultUrl + "favourite-color"));
        }

        static void printSecret(SecretBundle secret)
        {
            Console.WriteLine(string.Format("id: {0}, value: {1}", secret.SecretIdentifier.Name, secret.Value.ToString()));
        }

        static async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            var clientCredential = new ClientCredential(aadClientID, aadClientSecret);
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, clientCredential);
            return result.AccessToken;
        }

        static async Task<string> GetAccessTokenViaCert(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, AssertionCert);
            return result.AccessToken;
        }

        static void GetAssertionCert()
        {
            var clientAssertionCertPfx = FindCertificateByThumbprint(certThumbPrint);
            AssertionCert = new ClientAssertionCertificate(aadClientID, clientAssertionCertPfx);
        }

        static X509Certificate2 FindCertificateByThumbprint(string findValue)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindByThumbprint, findValue, false);
                if (col == null || col.Count == 0)
                    return null;
                return col[0];
            }
            finally
            {
                store.Close();
            }
        }
    }
}