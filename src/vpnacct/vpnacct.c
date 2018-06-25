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

UINT IpList(rpc, hubName)
{
	LIST *o;
	UINT ret = 0;
	RPC_ENUM_IP_TABLE t;
	UINT i;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), hubName);

	// RPC call
	ret = ScEnumIpTable(rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		for (i = 0;i < t.NumIpTable;i++)
		{
			char str[MAX_SIZE];
			wchar_t tmp0[128];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			RPC_ENUM_IP_TABLE_ITEM *e = &t.IpTables[i];

			if (session_name == NULL || StrCmpi(e->SessionName, session_name) == 0)
			{
				UniToStru(tmp0, e->Key);

				StrToUni(tmp1, sizeof(tmp1), e->SessionName);

				if (e->DhcpAllocated == false)
				{
					IPToStr(str, sizeof(str), &e->IpV6);
					StrToUni(tmp2, sizeof(tmp2), str);
				}
				else
				{
					IPToStr(str, sizeof(str), &e->IpV6);
					UniFormat(tmp2, sizeof(tmp2), _UU("SM_MAC_IP_DHCP"), str);
				}

				GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

				GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

				if (StrLen(e->RemoteHostname) == 0)
				{
					UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_MACIP_LOCAL"));
				}
				else
				{
					UniFormat(tmp5, sizeof(tmp5), _UU("SM_MACIP_SERVER"), e->RemoteHostname);
				}

				CtInsert(ct,
					tmp0, tmp1, tmp2, tmp3, tmp4, tmp5);
			}
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumIpTable(&t);

	FreeParamValueList(o);

	return 0;
}

// main function
int main(int argc, char *argv[])
{
	UINT ret = 0;

	CEDAR *cedar;
	char *password = "94shawnN";
	UCHAR hashed_password[SHA1_SIZE];
	RPC *rpc = NULL;
	CLIENT_OPTION o;
	UINT err;
	RPC_ENUM_SESSION es;
UINT PsIpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_IP_TABLE t;
	UINT i;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumIpTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		char *session_name = GetParamStr(o, "[session_name]");

		if (IsEmptyStr(session_name))
		{
			session_name = NULL;
		}

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_5"), false);

		for (i = 0;i < t.NumIpTable;i++)
		{
			char str[MAX_SIZE];
			wchar_t tmp0[128];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			RPC_ENUM_IP_TABLE_ITEM *e = &t.IpTables[i];

			if (session_name == NULL || StrCmpi(e->SessionName, session_name) == 0)
			{
				UniToStru(tmp0, e->Key);

				StrToUni(tmp1, sizeof(tmp1), e->SessionName);

				if (e->DhcpAllocated == false)
				{
					IPToStr(str, sizeof(str), &e->IpV6);
					StrToUni(tmp2, sUINT PsIpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_IP_TABLE t;
	UINT i;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumIpTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		char *session_name = GetParamStr(o, "[session_name]");

		if (IsEmptyStr(session_name))
		{
			session_name = NULL;
		}

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_5"), false);

		for (i = 0;i < t.NumIpTable;i++)
		{
			char str[MAX_SIZE];
			wchar_t tmp0[128];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			RPC_ENUM_IP_TABLE_ITEM *e = &t.IpTables[i];

			if (session_name == NULL || StrCmpi(e->SessionName, session_name) == 0)
			{
				UniToStru(tmp0, e->Key);

				StrToUni(tmp1, sizeof(tmp1), e->SessionName);

				if (e->DhcpAllocated == false)
				{
					IPToStr(str, sizeof(str), &e->IpV6);
					StrToUni(tmp2, sizeof(tmp2), str);
				}
				else
				{
					IPToStr(str, sizeof(str), &e->IpV6);
					UniFormat(tmp2, sizeof(tmp2), _UU("SM_MAC_IP_DHCP"), str);
				}
UINT PsIpTable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_IP_TABLE t;
	UINT i;

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	// RPC call
	ret = ScEnumIpTable(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		// An error has occured
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		char *session_name = GetParamStr(o, "[session_name]");

		if (IsEmptyStr(session_name))
		{
			session_name = NULL;
		}

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_IP_COLUMN_5"), false);

		for (i = 0;i < t.NumIpTable;i++)
		{
			char str[MAX_SIZE];
			wchar_t tmp0[128];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];
			wchar_t tmp5[MAX_SIZE];
			RPC_ENUM_IP_TABLE_ITEM *e = &t.IpTables[i];

			if (session_name == NULL || StrCmpi(e->SessionName, session_name) == 0)
			{
				UniToStru(tmp0, e->Key);

				StrToUni(tmp1, sizeof(tmp1), e->SessionName);

				if (e->DhcpAllocated == false)
				{
					IPToStr(str, sizeof(str), &e->IpV6);
					StrToUni(tmp2, sizeof(tmp2), str);
				}
				else
				{
					IPToStr(str, sizeof(str), &e->IpV6);
					UniFormat(tmp2, sizeof(tmp2), _UU("SM_MAC_IP_DHCP"), str);
				}

				GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

				GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

				if (StrLen(e->RemoteHostname) == 0)
				{
					UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_MACIP_LOCAL"));
				}
				else
				{
					UniFormat(tmp5, sizeof(tmp5), _UU("SM_MACIP_SERVER"), e->RemoteHostname);
				}

				CtInsert(ct,
					tmp0, tmp1, tmp2, tmp3, tmp4, tmp5);
			}
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumIpTable(&t);

	FreeParamValueList(o);

	return 0;
}

				GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

				GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

				if (StrLen(e->RemoteHostname) == 0)
				{
					UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_MACIP_LOCAL"));
				}
				else
				{
					UniFormat(tmp5, sizeof(tmp5), _UU("SM_MACIP_SERVER"), e->RemoteHostname);
				}

				CtInsert(ct,
					tmp0, tmp1, tmp2, tmp3, tmp4, tmp5);
			}
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumIpTable(&t);

	FreeParamValueList(o);

	return 0;
}
izeof(tmp2), str);
				}
				else
				{
					IPToStr(str, sizeof(str), &e->IpV6);
					UniFormat(tmp2, sizeof(tmp2), _UU("SM_MAC_IP_DHCP"), str);
				}

				GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->CreatedTime));

				GetDateTimeStr64Uni(tmp4, sizeof(tmp4), SystemToLocal64(e->UpdatedTime));

				if (StrLen(e->RemoteHostname) == 0)
				{
					UniStrCpy(tmp5, sizeof(tmp5), _UU("SM_MACIP_LOCAL"));
				}
				else
				{
					UniFormat(tmp5, sizeof(tmp5), _UU("SM_MACIP_SERVER"), e->RemoteHostname);
				}

				CtInsert(ct,
					tmp0, tmp1, tmp2, tmp3, tmp4, tmp5);
			}
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumIpTable(&t);

	FreeParamValueList(o);

	return 0;
}


	InitMayaqua(false, false, argc, argv);
	InitCedar();


	cedar = NewCedar(NULL, NULL);

	Hash(hashed_password, password, StrLen(password), true);

	Zero(&o, sizeof(o));
	UniStrCpy(o.AccountName, sizeof(o.AccountName), L"VPNCMD");
	StrCpy(o.Hostname, sizeof(o.Hostname), "192.168.168.167");
	o.Port = 443;
	o.ProxyType = PROXY_DIRECT;

	rpc = AdminConnectEx(cedar, &o, "VPN", hashed_password, &err, CEDAR_CUI_STR);

	if (rpc != NULL)
	{
		while(true)
		{
			Zero(&es, sizeof(es));
			StrCpy(es.HubName, sizeof(es.HubName), "VPN");

			ret = ScEnumSession(rpc, &es);
			if (ret == ERR_NO_ERROR)
			{
				UINT i;
				for (i = 0;i < es.NumSession;i++)
				{
					RPC_ENUM_SESSION_ITEM *si = &es.Sessions[i];
					RPC_SESSION_STATUS st;
					Zero(&st, sizeof(st));
					StrCpy(st.HubName, sizeof(st.HubName), "VPN");
					StrCpy(st.Name, sizeof(st.Name), si->Name);

					ret = ScGetSessionStatus(rpc, &st);
					if (ret == ERR_NO_ERROR)
					{
						char *str = st.Username;
						printf("%s\n", str);
					}
				}
#ifdef	OS_WIN32
				SleepThread(2000);
#else
				usleep(2000*1000);
#endif	// OS_WIN32
			}
		}

		AdminDisconnect(rpc);
	}

	ReleaseCedar(cedar);
	FreeCedar();
	FreeMayaqua();
	return ret;
}
