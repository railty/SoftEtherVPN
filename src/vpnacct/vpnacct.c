// SoftEther VPN Source Code - Stable Edition Repository
// Cedar Communication Module
// 
// SoftEther VPN Server, Client and Bridge are free software under GPLv2.
// 
// Copyright (c) Daiyuu Nobori.
// Copyright (c) SoftEther VPN Project, University of Tsukuba, Japan.
// Copyright (c) SoftEther Corporation.
// 
// All Rights Reserved.
// 
// http://www.softether.org/
// 
// Author: Daiyuu Nobori, Ph.D.
// Comments: Tetsuo Sugiyama, Ph.D.
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// version 2 as published by the Free Software Foundation.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License version 2
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// 
// THE LICENSE AGREEMENT IS ATTACHED ON THE SOURCE-CODE PACKAGE
// AS "LICENSE.TXT" FILE. READ THE TEXT FILE IN ADVANCE TO USE THE SOFTWARE.
// 
// 
// THIS SOFTWARE IS DEVELOPED IN JAPAN, AND DISTRIBUTED FROM JAPAN,
// UNDER JAPANESE LAWS. YOU MUST AGREE IN ADVANCE TO USE, COPY, MODIFY,
// MERGE, PUBLISH, DISTRIBUTE, SUBLICENSE, AND/OR SELL COPIES OF THIS
// SOFTWARE, THAT ANY JURIDICAL DISPUTES WHICH ARE CONCERNED TO THIS
// SOFTWARE OR ITS CONTENTS, AGAINST US (SOFTETHER PROJECT, SOFTETHER
// CORPORATION, DAIYUU NOBORI OR OTHER SUPPLIERS), OR ANY JURIDICAL
// DISPUTES AGAINST US WHICH ARE CAUSED BY ANY KIND OF USING, COPYING,
// MODIFYING, MERGING, PUBLISHING, DISTRIBUTING, SUBLICENSING, AND/OR
// SELLING COPIES OF THIS SOFTWARE SHALL BE REGARDED AS BE CONSTRUED AND
// CONTROLLED BY JAPANESE LAWS, AND YOU MUST FURTHER CONSENT TO
// EXCLUSIVE JURISDICTION AND VENUE IN THE COURTS SITTING IN TOKYO,
// JAPAN. YOU MUST WAIVE ALL DEFENSES OF LACK OF PERSONAL JURISDICTION
// AND FORUM NON CONVENIENS. PROCESS MAY BE SERVED ON EITHER PARTY IN
// THE MANNER AUTHORIZED BY APPLICABLE LAW OR COURT RULE.
// 
// USE ONLY IN JAPAN. DO NOT USE THIS SOFTWARE IN ANOTHER COUNTRY UNLESS
// YOU HAVE A CONFIRMATION THAT THIS SOFTWARE DOES NOT VIOLATE ANY
// CRIMINAL LAWS OR CIVIL RIGHTS IN THAT PARTICULAR COUNTRY. USING THIS
// SOFTWARE IN OTHER COUNTRIES IS COMPLETELY AT YOUR OWN RISK. THE
// SOFTETHER VPN PROJECT HAS DEVELOPED AND DISTRIBUTED THIS SOFTWARE TO
// COMPLY ONLY WITH THE JAPANESE LAWS AND EXISTING CIVIL RIGHTS INCLUDING
// PATENTS WHICH ARE SUBJECTS APPLY IN JAPAN. OTHER COUNTRIES' LAWS OR
// CIVIL RIGHTS ARE NONE OF OUR CONCERNS NOR RESPONSIBILITIES. WE HAVE
// NEVER INVESTIGATED ANY CRIMINAL REGULATIONS, CIVIL LAWS OR
// INTELLECTUAL PROPERTY RIGHTS INCLUDING PATENTS IN ANY OF OTHER 200+
// COUNTRIES AND TERRITORIES. BY NATURE, THERE ARE 200+ REGIONS IN THE
// WORLD, WITH DIFFERENT LAWS. IT IS IMPOSSIBLE TO VERIFY EVERY
// COUNTRIES' LAWS, REGULATIONS AND CIVIL RIGHTS TO MAKE THE SOFTWARE
// COMPLY WITH ALL COUNTRIES' LAWS BY THE PROJECT. EVEN IF YOU WILL BE
// SUED BY A PRIVATE ENTITY OR BE DAMAGED BY A PUBLIC SERVANT IN YOUR
// COUNTRY, THE DEVELOPERS OF THIS SOFTWARE WILL NEVER BE LIABLE TO
// RECOVER OR COMPENSATE SUCH DAMAGES, CRIMINAL OR CIVIL
// RESPONSIBILITIES. NOTE THAT THIS LINE IS NOT LICENSE RESTRICTION BUT
// JUST A STATEMENT FOR WARNING AND DISCLAIMER.
// 
// 
// SOURCE CODE CONTRIBUTION
// ------------------------
// 
// Your contribution to SoftEther VPN Project is much appreciated.
// Please send patches to us through GitHub.
// Read the SoftEther VPN Patch Acceptance Policy in advance:
// http://www.softether.org/5-download/src/9.patch
// 
// 
// DEAR SECURITY EXPERTS
// ---------------------
// 
// If you find a bug or a security vulnerability please kindly inform us
// about the problem immediately so that we can fix the security problem
// to protect a lot of users around the world as soon as possible.
// 
// Our e-mail address for security reports is:
// softether-vpn-security [at] softether.org
// 
// Please note that the above e-mail address is not a technical support
// inquiry address. If you need technical assistance, please visit
// http://www.softether.org/ and ask your question on the users forum.
// 
// Thank you for your cooperation.
// 
// 
// NO MEMORY OR RESOURCE LEAKS
// ---------------------------
// 
// The memory-leaks and resource-leaks verification under the stress
// test has been passed before release this source code.


// vpncmd.c
// VPN Command Line Management Utility

#include <GlobalConst.h>

#ifdef	WIN32
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <shlobj.h>
#include <commctrl.h>
#include <Dbghelp.h>
#endif	// WIN32
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <time.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

int accounting(RPC *rpc, char *hub_name)
{
	UINT ret;
	RPC_ENUM_IP_TABLE ip_table;

	Zero(&ip_table, sizeof(ip_table));
	StrCpy(ip_table.HubName, sizeof(ip_table.HubName), hub_name);

	// RPC call
	ret = ScEnumIpTable(rpc, &ip_table);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		return ret;
	}
	else
	{
		RPC_ENUM_SESSION enum_session;

		Zero(&enum_session, sizeof(enum_session));
		StrCpy(enum_session.HubName, sizeof(enum_session.HubName), hub_name);

		// RPC call
		ret = ScEnumSession(rpc, &enum_session);

		if (ret != ERR_NO_ERROR)
		{
			return ret;
		}
		else
		{
			UINT i;
			for (i = 0;i < enum_session.NumSession;i++)
			{
				RPC_SESSION_STATUS session_status;
				RPC_ENUM_SESSION_ITEM *session_item = &enum_session.Sessions[i];

				if (SearchStri(session_item->Name, "SID-LOCALBRIDGE", 0) == 0) continue;

				Zero(&session_status, sizeof(session_status));
				StrCpy(session_status.HubName, sizeof(session_status.HubName), hub_name);
				StrCpy(session_status.Name, sizeof(session_status.Name), session_item->Name);

				// RPC call
				ret = ScGetSessionStatus(rpc, &session_status);

				if (ret != ERR_NO_ERROR)
				{
					return ret;
				}
				else
				{
					UINT frame_ip = 0;
					UINT k;
					for (k = 0;k < ip_table.NumIpTable;k++)
					{
						RPC_ENUM_IP_TABLE_ITEM *ip_table_item = &ip_table.IpTables[k];
						if (StrCmpi(ip_table_item->SessionName, session_item->Name) == 0)
						{
							frame_ip = ip_table_item->Ip;
							break;
						}
					}
					if (frame_ip!=0)
					{
						UINT64 now;
						UINT diff;
						char recv_str[128];
						char send_str[128];
						char now_str[MAX_SIZE];
						char starttm_str[MAX_SIZE];
						char frame_ip_str[20];
						char client_ip_str[20];
						char server_ip_str[20];
						IPToStr32(frame_ip_str, sizeof(frame_ip_str), frame_ip);
						IPToStr32(server_ip_str, sizeof(server_ip_str), session_status.NodeInfo.ServerIpAddress);
						IPToStr32(client_ip_str, sizeof(client_ip_str), session_status.ClientIp);

						now = Tick64ToTime64(Tick64());
						ToStr64(now_str, now/1000);

						diff = (UINT)(now - session_status.Status.StartTime) / 1000;
						ToStr64(starttm_str, session_status.Status.StartTime);

						ToStr64(recv_str, session_status.Status.TotalRecvSize);
						ToStr64(send_str, session_status.Status.TotalSendSize);

						printf(
						"Service-Type = Framed-User\n"
						"Framed-Protocol = PPP\n"
						"NAS-Port = %u\n"
						"NAS-Port-Type = Async\n"
						"User-Name = '%s'\n"
						"Calling-Station-Id = '%s'\n"
						"Called-Station-Id = '%s'\n"
						"Acct-Session-Id = '%s-%s'\n"
						"Framed-IP-Address = %s\n"
						"Acct-Authentic = RADIUS\n"
						"Event-Timestamp = %s\n"
						"Acct-Session-Time = %u\n"
						"Acct-Input-Octets = %s\n"
						"Acct-Output-Octets = %s\n"
						"Acct-Status-Type = Interim-Update\n"
						"NAS-Identifier = '%s'\n"
						"Acct-Delay-Time = 0\n"
						"NAS-IP-Address = %s\n\n",
						Endian32(session_status.NodeInfo.ServerPort), 
						session_status.Username,
						client_ip_str,
						server_ip_str,
						session_status.Name, starttm_str,
						frame_ip_str,
						now_str,
						diff,
						recv_str,
						send_str,
						server_ip_str,
						server_ip_str
						);
					}
				}
				FreeRpcSessionStatus(&session_status);
			}
		}
		FreeRpcEnumSession(&enum_session);
	}
	FreeRpcEnumIpTable(&ip_table);
	return ret;
}
// main function
int main(int argc, char *argv[])
{
UINT ret = 0;
UINT err;
CEDAR *cedar;

UINT sleep_time = 5; //seconds
FOLDER *config;
char server_ip[20];
char server_pass[20];

char mode[20]; //radclient for now, radapi, mysql direct later
char radius_server[20];
char radius_secret[20];

char hub_name[20];
UINT server_port;
UCHAR hashed_server_pass[SHA1_SIZE];

wchar_t config_file[MAX_PATH];
wchar_t path_config_file[MAX_PATH];

RPC *rpc = NULL;
CLIENT_OPTION client_option;

	InitMayaqua(false, false, argc, argv);
	InitCedar();
	cedar = NewCedar(NULL, NULL);

	GetCurrentDirW(path_config_file, MAX_PATH);
	CombinePathW(config_file, sizeof(config_file), path_config_file, L"vpnacct.config");
	config = CfgReadW(config_file);
	CfgGetStr(config, "SE_Server_IP", server_ip, 20);
	server_port = CfgGetInt(config, "SE_Server_PORT");
	CfgGetStr(config, "SE_HUB", hub_name, 20);
	CfgGetStr(config, "SE_Server_PASS", server_pass, 20);
	sleep_time = CfgGetInt(config, "Sleep");

	CfgGetStr(config, "Mode", mode, 20);
	CfgGetStr(config, "Radius_Server", radius_server, 20);
	CfgGetStr(config, "Radius_Secret", radius_secret, 20);

	Hash((void*)hashed_server_pass, server_pass, StrLen(server_pass), true);

	Zero(&client_option, sizeof(client_option));
	UniStrCpy(client_option.AccountName, sizeof(client_option.AccountName), L"VPNCMD");
	StrCpy(client_option.Hostname, sizeof(client_option.Hostname), server_ip);
	client_option.Port = server_port;
	client_option.ProxyType = PROXY_DIRECT;

	rpc = AdminConnectEx(cedar, &client_option, "VPN", hashed_server_pass, &err, CEDAR_CUI_STR);

	if (rpc != NULL)
	{
		//for (;;)
		//{
			ret = accounting(rpc, hub_name);
//			SleepThread(sleep_time*1000);
		//}
		
		AdminDisconnect(rpc);
	}

	ReleaseCedar(cedar);
	FreeCedar();
	FreeMayaqua();
	//getchar();
	return ret;
}

