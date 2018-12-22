#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2018, Kendrick Walls
# ......................................................................
# Licensed under MIT (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# ......................................................................
# http://www.github.com/reactive-firewall/PiAP-python-tools/LICENSE.rst
# ......................................................................
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ......................................................................

"""
TOOL PROVIDED AS IS. NO WARENTY. USE AT OWN RISK.
THERE MAY BE REGULATIONS GOVERNING USE OF WIFI SETTINGS IN MANY AREAS.
"""

""" THIS CODE IS NOT IN A USEABLE STATE """

try:
	import sys
	import os
	import argparse
	if str("compile_interface") in __file__:
		__sys_path__ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
		if __sys_path__ not in sys.path:
			sys.path.insert(0, __sys_path__)
except Exception:
	raise ImportError("Pocket Knife Unit PKU failed to import.")


try:
	from . import remediation as remediation
except Exception:
	try:
		import remediation as remediation
	except Exception:
		raise ImportError("Error Importing remediation")


try:
	from . import utils as utils
except Exception:
	try:
		import utils as utils
	except Exception:
		raise ImportError("Error Importing utils")

__prog__ = """piaplib.pku.compile_interface"""


HEADER_CHUNK = u'# interfaces(5) file used by ifup(8) and ifdown(8)\
\
# Please note that this file is written to be used with dhcpcd\
# For static IP, consult /etc/dhcpcd.conf and \'man dhcpcd.conf\'\
\
# Include files from /etc/network/interfaces.d:\
source-directory /etc/network/interfaces.d\
\
iface lo inet loopback\
'
"""the header of the whole config /etc/network/interfaces file"""


MEDIA_TYPES = [u'eth', u'wlan', u'vnet', u'br', u'usb']
""" Prefixes for interfaces """

ZONE_TYPES = [u'WAN', u'LAN', u'DMZ', u'MON']
""" Prefixes for zones """

WIFI_CONFIG_TEMPLATE = str(
	"""	wireless-ap {}
	wireless-essid {}
	wireless-rate {}
	wireless-txpower {}
	wireless-channel auto
	wireless-frag {}
	wireless-mode {}
	"""
)
"""Template for configuring wifi settings"""

WIFI_MODE_TYPES = [u'Managed', u'Ad-Hoc', u'Secondary', u'Repeater', u'Monitor', 'Master']
"""Values for 802.11 modes via wireless-mode field"""

WIFI_POWER_MODES = [u'on', u'off']
"""Values for wireless card energy eficency modes via wireless-power field"""

WIFI_TRANSMITER_POWERS = [u'auto', u'off']
"""Values for wireless card TX power modes via wireless-txpower field. only supports auto or off."""

WIFI_FRAG_MODES = [u'auto', u'off']
"""Values for wireless fragment retry modes via wireless-frag field. only supports auto or off."""

WIFI_CHANNELS = [
	u'auto',
	u'1',
	u'2',
	u'3',
	u'4',
	u'5',
	u'6',
	u'7',
	u'8',
	u'9',
	u'10',
	u'11',
	u'12',
	u'13',
	u'14',
	u'34',
	u'36',
	u'38',
	u'40',
	u'42',
	u'44',
	u'46',
	u'48',
	u'149',
	u'151',
	u'153',
	u'155',
	u'157',
	u'159',
	u'161',
	u'165'
]
"""
Values for 802.11 wireless channels for the wireless-channel field.
only supports auto right now.
"""

WIFI_5_CHANNELS_UI_ALLOWED = [u'auto', u'64', u'153']
"""5GHz recommended channel setings."""

WIFI_CHANNELS_UI_CHOICES = [
	u'auto', u'1', u'2', u'3', u'4', u'5',
	u'6', u'7', u'8', u'9', u'10', u'11',
	u'12', u'13', u'14', u'64', u'149', u'153'
]
"""Recommended channel setings."""

WIFI_CHANNELS_DFS_REQUIRED = [
	u'7', u'8', u'9', u'11', u'12', u'13', u'14',
	u'16', u'50', u'52', u'56', u'58', u'60', u'62',
	u'64', u'100', u'102', u'104', u'106', u'108', u'110',
	u'112', u'114', u'116', u'118', u'120', u'122', u'124',
	u'126', u'128', u'132', u'134', u'136', u'138', u'140',
	u'144', u'183', u'184', u'185', u'187', u'188', u'189',
	u'192', u'196'
]
"""good faith effort to restrict WIFI channels. USE AT OWN RISK."""

WIFI_SEC_MODES = [None, u'WEP', u'WPA2', u'WPA-legacy', u'WPA-Enterprise']

WPA2_MODE = u'RSN'


def addWiFiArgs(parser=None):
	"""Parses the arguments for the WAN WiFi client mode."""
	wifi_parser = parser.add_argument_group(title="Wireless", description="Wireless options")
	try:
		wifi_parser.add_argument(
			'--mode', dest='wireless_mode_type',
			default=WIFI_MODE_TYPES[0],
			choices=WIFI_MODE_TYPES, required=False,
			help='802.11 wifi mode'
		)
		wifi_parser.add_argument(
			'--manage-hardware-power',
			dest='wireless_power_mode',
			default=WIFI_POWER_MODES[0],
			choices=WIFI_POWER_MODES,
			required=False,
			help='WiFi Hardware power mode. (auto or off)'
		)
		wifi_parser.add_argument(
			'--manage-signal-power',
			dest='wireless_txpower_mode',
			default=WIFI_TRANSMITER_POWERS[0],
			choices=WIFI_TRANSMITER_POWERS,
			required=False,
			help='WiFi signal strength mode. (auto or off)'
		)
		wifi_parser.add_argument(
			'--manage-frag',
			dest='wireless_frag_mode',
			default=WIFI_FRAG_MODES[0],
			choices=WIFI_FRAG_MODES, required=False,
			help='WiFi Fragment resend mode. (auto or off)'
		)
		wifi_parser.add_argument(
			'-c',
			'--channel',
			dest='wireless_channel_mode',
			default=WIFI_CHANNELS[0],
			choices=WIFI_CHANNELS,
			required=False,
			help='WiFi channel band. (defaults to auto)'
		)
		wifi_parser.add_argument(
			'--security',
			dest=u'wireless_security',
			default=WIFI_SEC_MODES[2],
			choices=WIFI_SEC_MODES,
			required=False,
			help='wifi security. (defaults to wpa2)'
		)
		wifi_parser.add_argument(
			'--ap',
			default=u'any',
			required=False,
			help='STATIC - Access Point MAC address'
		)
		wifi_parser.add_argument(
			'--ssid',
			default=None,
			required=False,
			help='STATIC - SSID. WiFi Name'
		)
	except Exception as err:
		print(str(err))
		print(str((err.args)))
		raise argparse.ArgumentError(err)
	return parser


@remediation.error_handling
def generateParser(calling_parser_group):
	"""Parses the CLI arguments."""
	if calling_parser_group is None:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description='Handles PiAP pocket version reports',
			epilog="PiAP Book Controller for version tools."
		)
	else:
		parser = calling_parser_group.add_parser(
			str(__prog__).split(".")[-1], help="PiAP Book Controller for version tools."
		)
	try:
		parser = argparse.ArgumentParser(
			prog='compile_interface',
			description='compile iface def'
		)
		parser.add_argument(
			'-t',
			'--type',
			dest='media_type',
			default=MEDIA_TYPES[0],
			choices=MEDIA_TYPES,
			help='usb or ethernet or wireless'
		)
		parser.add_argument(
			'-z',
			'--zone',
			default=ZONE_TYPES[0],
			choices=ZONE_TYPES,
			help='WAN or LAN'
		)
		group_static = parser.add_mutually_exclusive_group()
		group_static.add_argument(
			'-S',
			'--static',
			dest=u'is_static',
			action='store_true',
			help='use static ip'
		)
		group_static.add_argument(
			'-d',
			'--dhcp',
			dest=u'is_static',
			action='store_false',
			help='use dynamic ip via dhcp. This is default.'
		)
		parser.add_argument('-i', '--ip', default=None, help='STATIC - IP')
		parser.add_argument('-n', '--netmask', default=None, help='STATIC - Netmask')
		parser.add_argument('-g', '--gw', default=None, help='STATIC - the gw IP')
		parser.add_argument('-v', '--vlanid', dest='vlanid', default=None, help='the vlan')
		parser = utils._handleVersionArgs(parser)
		parser = addWiFiArgs(parser)
	except Exception as err:
		print(str(type(err)))
		print(str(err))
		print(str((err.args)))
		parser.error("parser tool bug")
		return None
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = generateParser(None)
	return parser.parse_args(arguments)


def compile_iface_name(media_type='eth', index=0, vlanID=None):
	theResult = u'vnet1'
	if media_type in MEDIA_TYPES:
		theResult = str(str(u'{}{}').format(media_type, index))
	if vlanID is not None:
		temp = str(u'{}.{}').format(theResult, vlanID)
		theResult = str(temp)
		del temp
	return theResult


def compile_pre_up_line(iface='vnet1', use_ipv6=False, gateway_ip=None):
	theResult = None
	if use_ipv6 is False:
		theResult = str(
			str(
				u'pre-up sysctl -w net.ipv6.conf.{}.disable_ipv6=1 ' +
				u'2>/dev/null ; wait ; ip link set {} up'
			).format(iface, iface)
		)
	else:
		theResult = str(str(u'pre-up ip link set {} up').format(iface))
	if gateway_ip is not None:
		temp = str(u'{} ; ip route add default via {} dev {}').format(theResult, gateway_ip, iface)
		theResult = str(temp)
		del temp
	return theResult


def compile_post_down_line(gateway_ip=None):
	temp = str(u'post-down')
	if gateway_ip is not None:
		temp = str(
			u'post-down ip route del default via {} dev {} ; wait ;'
		).format(gateway_ip, u'${IFACE}')
	theResult = str(str(u'{} ip link set {} down ; wait ;').format(temp, u'${IFACE}'))
	return theResult


def compile_iface(
	media_type='eth', index=0,
	vlanID=None, mode='dhcp',
	static_ip=None, netmask=u'255.255.255.0',
	gateway_ip=None, use_ipv6=False
):
	"""Compiles the iface def."""
	theResult = str('allow-hotplug {}').format(compile_iface_name(media_type, index, vlanID))
	theResult = theResult + u'\n' + str(
		u'iface {} inet {}'
	).format(compile_iface_name(media_type, index, vlanID), mode)
	if mode in u'static':
		theResult = theResult + u'\n\t' + str(
			'address {}\n\tnetmask {}\n\tgateway {}'
		).format(static_ip, netmask, gateway_ip)
	theResult = theResult + u'\n\t' + compile_pre_up_line(
		compile_iface_name(media_type, index, None), use_ipv6, gateway_ip
	)
	theResult = theResult + u'\n\t' + str(
		u'post-up sudo ip addr del $(ip addr show ${IFACE:-eth0}' +
		u'| fgrep 169.254 | grepCIDR | grepCIDR -m1) dev ${IFACE} 2>/dev/null || true'
	)
	theResult = theResult + u'\n\t' + compile_post_down_line(gateway_ip)
	if vlanID is not None:
		theResult = theResult + u'\n\tvlan-raw-device ' + compile_iface_name(
			media_type, index, None
		)
	return theResult


@remediation.bug_handling
def main(argv=None):
	"""The Main Event."""
	args = parseArgs(argv)
	interface_type = args.media_type
	interface_zone = args.zone
	if str(str(interface_zone).upper()) in "WAN":
		interface_index = 0
	elif str(str(interface_zone).upper()) in "LAN":
		interface_index = 1
	interface_is_static = (args.is_static is True)
	if (args.vlanid is not None):
		interface_vlanID = args.vlanid
		if interface_vlanID is not None:
			raise NotImplementedError("[CWE-758] BUG - Not Implemented Yet.")
	interface_mode = u'manual'
	interface_gateway = None
	interface_ip = None
	interface_netmask = u'255.255.255.0'
	if interface_is_static is True:
		interface_mode = u'static'
		interface_gateway = args.gw
		interface_ip = args.ip
		interface_netmask = args.netmask
	else:
		interface_mode = u'dhcp'
	print(
		str(
			compile_iface(
				interface_type, interface_index,
				None, interface_mode,
				interface_ip, interface_netmask,
				interface_gateway, False
			)
		)
	)
	return 0


if __name__ in u'__main__':
	try:
		if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
			exit(main(sys.argv[1:]))
		else:
			exit(main(["--help"]))
	except Exception:
		raise ImportError("Error running main")
	exit(0)

