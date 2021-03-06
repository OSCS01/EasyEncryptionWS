﻿using System;
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
        public List<string> Download(string user, string filename, string share, string owner)
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
        public bool loginValidation(string username, string password)
        {
            byte[] data = Encoding.UTF8.GetBytes(password);
            SHA256Managed alg = new SHA256Managed();
            byte[] hash = alg.ComputeHash(data);
            string hashString = string.Empty;
            foreach (byte x in hash)
            {
                hashString += String.Format("{0:x2}", x);
            }
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("Select Count(*) From Users where username = @username and pass = @hashString", con))
                {
                    cmd.Parameters.AddWithValue("@username", username);
                    cmd.Parameters.AddWithValue("@hashString", hashString);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    using (SqlDataAdapter sda = new SqlDataAdapter())
                    {
                        sda.SelectCommand = cmd;
                        DataTable dt = new DataTable();
                        sda.Fill(dt);
                        if (dt.Rows[0][0].ToString() == "1")
                        {
                            return true;

                        }
                        else
                        {
                            return false;
                        }

                    }

                        


                }
                    


            }

        }
        [WebMethod]
        public bool checkGroup(string newGroup)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT COUNT(*) FROM Groups WHERE GroupName like @newGroup", con))
                {
                    con.Open();
                    cmd.Parameters.AddWithValue("@newGroup", newGroup);
                    int groupCount = (int)cmd.ExecuteScalar();
                    if (groupCount > 0)
                    {
                        return true;
                    }
                    else
                    {
                        return false;

                    }
                }
            }
        }
        [WebMethod]
        public void addGroup(string username, string GroupName)
        {
            SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString);
            con.Open();
            SqlCommand cmd1 = new SqlCommand("INSERT INTO Groups(GroupName, owner) VALUES('" + GroupName + "','" + username+"')",con);
            cmd1.ExecuteNonQuery();
            SqlCommand cmd2 = new SqlCommand("INSERT INTO UsersGroups(username, GroupName) VALUES('" + username + "' , '" + GroupName + "')",con);
            cmd2.ExecuteNonQuery();
        }
        [WebMethod]
        public List<string> displayGrpMem(string GroupName)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT username FROM UsersGroups WHERE GroupName = @group"))
                {
                    cmd.Parameters.AddWithValue("@group", GroupName);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    using (SqlDataAdapter sda = new SqlDataAdapter())
                    {
                        sda.SelectCommand = cmd;
                        DataTable dt = new DataTable();
                        sda.Fill(dt);
                        List<string> memlist = new List<string>();
                        foreach (DataRow dr in dt.Rows)
                        {
                            memlist.Add(dr.ToString());
                        }
                        return memlist;
                    }
                }
            }
        }



        [WebMethod]
        public string getLogs(string name, string owner, string group)
        {
            return SerializeTableToString(retrieveLogs(name, owner, group),"AccessLogs");
        }

        [WebMethod]
        public List<string> getGroups(string username)
        {
            List<string> grouplist = new List<string>();
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT GroupName FROM UsersGroups WHERE username = @user"))
                {
                    cmd.Parameters.AddWithValue("@user", username);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    SqlDataReader rd = cmd.ExecuteReader();
                    if (rd.HasRows)
                    {
                        while (rd.Read())
                        {
                            grouplist.Add(rd.GetString(0));
                        }
                    }
                    return grouplist;
                }
            }
        }
        [WebMethod]
        public DataTable displayGroupMem(string GroupName)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT username FROM UsersGroups WHERE GroupName = @group"))
                {
                    cmd.Parameters.AddWithValue("@group", GroupName);
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
        public string retrieveGroupMem(string GroupName)
        {
            DataTable dt = displayGroupMem(GroupName);
            string xml = SerializeTableToString(dt, "Members");
            return xml;
        }
        [WebMethod]
        public DataTable displayContacts()
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT name FROM Users"))
                {
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
        public string retrieveContacts()
        {
            DataTable dt = displayContacts();
            string xml = SerializeTableToString(dt, "Contacts");
            return xml;
        }
        [WebMethod]
        public void addGroupMem(string group, string name)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                SqlCommand cmd = new SqlCommand("INSERT INTO UsersGroups(username,GroupName) SELECT username, '" + group + "' FROM Users WHERE name = '" + name + "'");
                cmd.Connection = con;
                cmd.Connection.Open();
                cmd.ExecuteNonQuery();
            }
        }
        [WebMethod]
        public bool checkGrpMem(string GroupName, string name)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("Select Count(*) From UsersGroups where GroupName =@group and username = @name", con))
                {
                    cmd.Parameters.AddWithValue("@name", name);
                    cmd.Parameters.AddWithValue("@group", GroupName);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    using (SqlDataAdapter sda = new SqlDataAdapter())
                    {
                        sda.SelectCommand = cmd;
                        DataTable dt = new DataTable();
                        sda.Fill(dt);
                        if (dt.Rows[0][0].ToString() == "1")
                        {
                            return true;

                        }
                        else
                        {
                            return false;
                        }



                    }
                }

            }
        }
        [WebMethod]
        public string checkGrpOwner(string GroupName)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT owner FROM Groups WHERE GroupName = @GroupName"))
                {
                    cmd.Parameters.AddWithValue("@GroupName", GroupName);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    using (SqlDataReader rd = cmd.ExecuteReader())
                    {
                        rd.Read();
                        string owner = rd.GetString(0);
                        return owner;

                    }
                        
                }
                
                
            }
        }
        [WebMethod]
        public void DeleteGrp (string group)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {

                SqlCommand cmd1 = new SqlCommand("DELETE FROM UsersGroups WHERE GroupName = @group");
                cmd1.Parameters.AddWithValue("@group", group);
                cmd1.Connection = con;
                cmd1.Connection.Open();
                cmd1.ExecuteNonQuery();
                SqlCommand cmd2 = new SqlCommand("DELETE FROM Groups WHERE GroupName = @group");
                cmd2.Parameters.AddWithValue("@group", group);
                cmd2.Connection = con;
                cmd2.ExecuteNonQuery();
                //using (SqlCommand cmd = new SqlCommand("DELETE FROM UsersGroups WHERE GroupName = @group"))
                //{
                //    cmd.Parameters.AddWithValue("@group", group);
                //    cmd.Connection = con;
                //    cmd.Connection.Open();
                //    cmd.ExecuteNonQuery();
                //}

            }
        }

        [WebMethod]
        public void DeleteFile(string name, string owner, string group, string user)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("DELETE FROM AccessLogs WHERE OriginalFilename = @name AND Owner = @owner AND sharedGroup = @group"))
                {
                    cmd.Parameters.AddWithValue("@owner", owner);
                    cmd.Parameters.AddWithValue("@group", group);
                    cmd.Parameters.AddWithValue("@name", name);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    cmd.ExecuteNonQuery();
                    cmd.CommandText = "DELETE FROM Files WHERE OriginalFilename + OriginalFileExt = @name AND Owner = @owner AND sharedGroup = @group";
                    cmd.ExecuteNonQuery();
                }
            }
        }

        public DataTable retrieveLogs(string name, string owner, string group)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
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
            string xml = SerializeTableToString(dt,"Files");
            return xml;
        }


        public string decryptKey(string owner, string filename, string group, string pubkey)
        {
            CspParameters csp = new CspParameters();
            csp.KeyContainerName = "EEKeys";
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp))
            {
                string enckey = "";
                using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
                {
                    using (SqlCommand cmd = new SqlCommand("SELECT EncKey FROM [Files] WHERE Owner = @Owner AND OriginalFilename + OriginalFileExt = @filename AND sharedGroup = @group"))
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

        public string getUserPubKey(string user)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT PubKey FROM [Users] WHERE username = @user"))
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

        public List<string> DownloadFile(string owner, string filename, string share, string pubkey)
        {
            List<string> fi = new List<string>();
            CspParameters csp = new CspParameters();
            csp.KeyContainerName = "EEKeys";
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp))
            {
                using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
                {
                    using (SqlCommand cmd = new SqlCommand("SELECT IV,OriginalFilename,OriginalFileExt, EncKey, data FROM [Files] WHERE Owner = @owner AND OriginalFilename + OriginalFileExt = @filename AND sharedGroup = @share"))
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
                                    string enckey = rd.GetString(3);
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
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
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
        public bool uploadFiles(long size, string group, string owner, string originalfilename, string originalfileext, string encryptedkey, string IV, byte[] fileData)
        {
            try
            {
                using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
                {
                    using (SqlCommand cmd = new SqlCommand("INSERT INTO Files (Size,sharedGroup,Owner,OriginalFilename,OriginalFileExt,EncKey,IV, data) VALUES (@size,@group,@owner,@originalfilename,@originalfileext,@key,@IV,@data)"))
                    {
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
                        return true;
                    }
                }
            }
            catch (Exception e)
            {
                return false;
            }
        }

        [WebMethod]
        public int retrieveNotification(string username)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT (SELECT count(DISTINCT OriginalFilename) FROM Files WHERE Owner = @owner) - (SELECT count(DISTINCT OriginalFilename) FROM AccessLogs WHERE Owner = @owner)"))
                {
                    cmd.Parameters.AddWithValue("@owner", username);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    SqlDataReader rd = cmd.ExecuteReader();
                    rd.Read();
                    return rd.GetInt32(0);                    
                }
            }
        }

        [WebMethod]
        public bool getIsDownloaded(string filename, string username,string group)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT count(*) FROM AccessLogs WHERE UserDownload = @owner AND OriginalFilename = @filename AND sharedGroup = @group")) 
                {
                    cmd.Parameters.AddWithValue("@owner",username);
                    cmd.Parameters.AddWithValue("@filename",filename);
                    cmd.Parameters.AddWithValue("@group",group);
                    cmd.Connection = con;
                    cmd.Connection.Open();
                    SqlDataReader rd = cmd.ExecuteReader();
                    rd.Read();
                    if (rd.GetInt32(0) > 0)
                        return true;
                    else
                        return false;
                }
            }
        }

        public DataTable retrieveFiles(string username)
        {
            using (SqlConnection con = new SqlConnection(System.Configuration.ConfigurationManager.ConnectionStrings["PeteDB"].ConnectionString))
            {
                using (SqlCommand cmd = new SqlCommand("SELECT OriginalFilename + OriginalFileExt AS [Filename], OriginalFileExt as Extension, Size,sharedGroup,Owner FROM Files WHERE Owner = @owner OR sharedGroup IN (SELECT GroupName From UsersGroups WHERE username = @owner)"))
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



        public string SerializeTableToString(DataTable dt,string tablename)
        {
            using (var sw = new StringWriter())
            using (var tw = new XmlTextWriter(sw))
            {
                dt.TableName = tablename;

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
