using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Services;
using System.Xml;
using System.Xml.Serialization;

namespace EasyEncWS
{
    /// <summary>
    /// Summary description for MainService
    /// </summary>
    [WebService(Namespace = "http://tempuri.org/")]
    [WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
    [System.ComponentModel.ToolboxItem(false)]
    // To allow this Web Service to be called from script, using ASP.NET AJAX, uncomment the following line. 
    // [System.Web.Script.Services.ScriptService]
    public class MainService : System.Web.Services.WebService
    {
        [WebMethod]
        public string getPubkey()
        {
            CspParameters csp = new CspParameters();
            csp.KeyContainerName = "EEKeys";
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);
            string pubkeyxml = rsa.ToXmlString(true);
            return pubkeyxml;
        }
        [WebMethod]
        public List<string> Download(string user, string filename,string share,string owner)
        {
            string pubkey = getUserPubKey(user);
            List<string> fileitem = new List<string>();
            using (RSACryptoServiceProvider rsap = new RSACryptoServiceProvider())
            {
                rsap.FromXmlString(pubkey);
                fileitem = DownloadFile(owner, filename, share, pubkey);
                addLogs(filename, owner, user, share);
            }
            return fileitem;
        }

        [WebMethod]
        public string getLogs(string name,string owner,string group)
        {
            return SerializeTableToString(retrieveLogs(name, owner, group));
        }

        public DataTable retrieveLogs(string name, string owner, string group)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["EEDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT * FROM AccessLogs WHERE OriginalFilename = @name AND Owner = @owner AND sharedGroup = @group"))
                {
                    cmd.Parameters.AddWithValue("@owner", owner);
                    cmd.Parameters.AddWithValue("@group", group);
                    cmd.Parameters.AddWithValue("@name", name);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    using (SqlDataAdapter sda = new SqlDataAdapter())
                    {
                        sda.SelectCommand = cmd;
                        DataTable dt = new DataTable();
                        sda.Fill(dt);
                        return dt;
                    }
                }
            }
        }

        [WebMethod]
        public string retrieve(string user)
        {
            DataTable dt = retrieveFiles(user);
            string xml = SerializeTableToString(dt);
            return xml;
        }


        public string decryptKey(string owner, string filename,string group, string pubkey)
        {
            CspParameters csp = new CspParameters();
            csp.KeyContainerName = "EEKeys";
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp))
            {
                string enckey = "";
                using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["EEDB"].ConnectionString))
                {
                    using (SqlCommand cmd = new SqlCommand("SELECT EncKey FROM [Files] WHERE Owner = @Owner AND OriginalFilename + OriginalFileExt = @filename AND SharedGroups = @group"))
                    {
                        cmd.Parameters.AddWithValue("@Owner", owner);
                        cmd.Parameters.AddWithValue("@filename", filename);
                        cmd.Parameters.AddWithValue("@group", group);
                        cmd.Connection = con;
                        cmd.Connection.Open();
                        using (SqlDataReader rd = cmd.ExecuteReader())
                        {
                            if (rd.HasRows)
                            {
                                rd.Read();
                                enckey = rd.GetString(0);
                            }
                        }
                    }
                }
                byte[] deckey = rsa.Decrypt(Convert.FromBase64String(enckey), false);
                rsa.FromXmlString(pubkey);
                byte[] reenckey = rsa.Encrypt(deckey, false);
                return Convert.ToBase64String(reenckey);
                
            }
        }

        public  string getUserPubKey(string user)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["EEDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT PubKey FROM [User] WHERE Username = @user"))
                {
                    cmd.Parameters.AddWithValue("@user", user);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    using (SqlDataReader rd = cmd.ExecuteReader())
                    {
                        if (rd.HasRows)
                        {
                            rd.Read();
                        }
                        return rd.GetString(0);
                    }
                }
            }
        }

        public List<string> DownloadFile(string owner, string filename, string share,string pubkey)
        {
            List<string> fi = new List<string>();
            CspParameters csp = new CspParameters();
            csp.KeyContainerName = "EEKeys";
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp))
            {
                using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["EEDB"].ConnectionString))
                {
                    using (SqlCommand cmd = new SqlCommand("SELECT HashedFilename,IV,OriginalFilename,OriginalFileExt, EncKey, data FROM [Files] WHERE Owner = @owner AND OriginalFilename + OriginalFileExt = @filename AND SharedGroups = @share"))
                    {
                        cmd.Parameters.AddWithValue("@owner", owner);
                        cmd.Parameters.AddWithValue("@filename", filename);
                        cmd.Parameters.AddWithValue("@share", share);
                        cmd.Connection = con;
                        cmd.Connection.Open();
                        using (SqlDataReader rd = cmd.ExecuteReader())
                        {
                            if (rd.HasRows)
                            {
                                while (rd.Read())
                                {
                                    fi.Add(rd.GetString(0));
                                    fi.Add(rd.GetString(1));
                                    fi.Add(rd.GetString(2));
                                    fi.Add(rd.GetString(3));
                                    string enckey = rd.GetString(4);
                                    byte[] deckey = rsa.Decrypt(Convert.FromBase64String(enckey), false);
                                    rsa.FromXmlString(pubkey);
                                    byte[] reenckey = rsa.Encrypt(deckey, false);
                                    fi.Add(Convert.ToBase64String(reenckey));
                                    fi.Add(Convert.ToBase64String(getFileData(rd)));
                                }
                            }
                            return fi;
                        }
                    }
                }
            }
        }

        //Honestly have no idea if this will work.
        public byte[] getFileData(SqlDataReader rd)
        {
            int ordinal = rd.GetOrdinal("data");

            if (!rd.IsDBNull(ordinal))
            {
                long size = rd.GetBytes(ordinal, 0, null, 0, 0);
                byte[] values = new byte[size];
                int bufferSize = 1024;
                long bytesRead = 0;
                int curPos = 0;

                while (bytesRead < size)
                {
                    bytesRead += rd.GetBytes(ordinal, curPos, values, curPos, bufferSize);
                    curPos += bufferSize;
                }
                return values;
            }
            else
                return null;
        }

        public void addLogs(string filename, string owner, string downloader, string group)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["EEDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("INSERT INTO AccessLogs (OriginalFilename,Owner,UserDownload,sharedGroup) VALUES (@filename,@owner,@user,@group)"))
                {
                    cmd.Parameters.AddWithValue("@filename", filename);
                    cmd.Parameters.AddWithValue("@owner", owner);
                    cmd.Parameters.AddWithValue("@user", downloader);
                    cmd.Parameters.AddWithValue("@group", group);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    cmd.ExecuteNonQuery();
                }
            }
        }
        [WebMethod]
        public void uploadFiles(string filename, long size, string group, string owner, string originalfilename, string originalfileext, string encryptedkey, string IV, byte[] fileData)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["EEDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("INSERT INTO Files (HashedFilename,Size,SharedGroups,Owner,OriginalFilename,OriginalFileExt,EncKey,IV, data) VALUES (@filename,@size,@group,@owner,@originalfilename,@originalfileext,@key,@IV,@data)"))
                {
                    cmd.Parameters.AddWithValue("@filename", filename);
                    cmd.Parameters.AddWithValue("@size", size);
                    cmd.Parameters.AddWithValue("@group", group);
                    cmd.Parameters.AddWithValue("@owner", owner);
                    cmd.Parameters.AddWithValue("@originalfilename", originalfilename);
                    cmd.Parameters.AddWithValue("@originalfileext", originalfileext);
                    cmd.Parameters.AddWithValue("@key", encryptedkey);
                    cmd.Parameters.AddWithValue("@IV", IV);
					cmd.Parameters.AddWithValue("@data", fileData);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    cmd.ExecuteNonQuery();
                }
            }
        }

        public DataTable retrieveFiles(string username)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["EEDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT OriginalFilename + OriginalFileExt AS [Filename],Size,SharedGroups,Owner FROM Files WHERE Owner = @owner"))
                {
                    cmd.Parameters.AddWithValue("@owner", username);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    using (SqlDataAdapter sda = new SqlDataAdapter())
                    {
                        sda.SelectCommand = cmd;
                        DataTable dt = new DataTable();
                        sda.Fill(dt);
                        return dt;
                    }
                }
            }
        }
        


        public string SerializeTableToString(DataTable dt)
        {
            using (var sw = new StringWriter())
            using (var tw = new XmlTextWriter(sw))
            {
                dt.TableName = @"AccessLogs";

                tw.Formatting = Formatting.Indented;

                tw.WriteStartDocument();
                tw.WriteStartElement(@"data");

                ((IXmlSerializable)dt).WriteXml(tw);

                tw.WriteEndElement();
                tw.WriteEndDocument();

                tw.Flush();
                tw.Close();
                sw.Flush();

                return sw.ToString();
            }
        }

    }
}
